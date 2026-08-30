use std::borrow::Cow;
use std::cell::Ref;
use std::fmt;

use html5ever::tendril::StrTendril;
use html5ever::tree_builder::{ElemName, ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::{Attribute as HtmlAttribute, LocalName, Namespace, QualName};
use markup5ever::TokenizerResult;

use crate::tree::{Attribute, DomTree, NodeData, NodeId, ShadowRootMode};

/// DOM's valid-shadow-host-name predicate. Gecko's
/// `nsContentUtils::IsValidShadowHostName` uses this same HTML allowlist plus
/// valid custom-element names; keeping the check at the parser boundary makes
/// an invalid declarative template fall back to an ordinary inert template.
fn is_valid_shadow_host(tree: &DomTree, id: NodeId) -> bool {
    let Some(node) = tree.get_node(id) else {
        return false;
    };
    let Some(name) = node.as_element() else {
        return false;
    };
    if name.ns != ns!(html) {
        return false;
    }
    let local = name.local.as_ref();
    if matches!(
        local,
        "article"
            | "aside"
            | "blockquote"
            | "body"
            | "div"
            | "footer"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "main"
            | "nav"
            | "p"
            | "section"
            | "span"
    ) {
        return true;
    }

    let mut chars = local.chars();
    if !chars.next().is_some_and(|first| first.is_ascii_lowercase())
        || !local.contains('-')
        || local.chars().any(|ch| {
            ch.is_ascii_uppercase()
                || ch == '\0'
                || matches!(
                    ch,
                    '\u{0009}' | '\u{000A}' | '\u{000C}' | '\u{000D}' | '\u{0020}'
                )
                || matches!(ch, '/' | '>')
        })
    {
        return false;
    }
    !matches!(
        local,
        "annotation-xml"
            | "color-profile"
            | "font-face"
            | "font-face-src"
            | "font-face-uri"
            | "font-face-format"
            | "font-face-name"
            | "missing-glyph"
    )
}

pub struct ObscuraElemName<'a> {
    _ref: Ref<'a, ()>,
    name: *const QualName,
}

impl<'a> fmt::Debug for ObscuraElemName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = unsafe { &*self.name };
        write!(f, "{:?}", name)
    }
}

impl<'a> ElemName for ObscuraElemName<'a> {
    fn ns(&self) -> &Namespace {
        unsafe { &(*self.name).ns }
    }

    fn local_name(&self) -> &LocalName {
        unsafe { &(*self.name).local }
    }
}

impl TreeSink for DomTree {
    type Handle = NodeId;
    type Output = Self;
    type ElemName<'a> = ObscuraElemName<'a>;

    fn finish(self) -> Self::Output {
        self
    }

    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> NodeId {
        self.document()
    }

    fn elem_name<'a>(&'a self, target: &'a NodeId) -> ObscuraElemName<'a> {
        let borrow = self.borrow_inner();
        let node = borrow
            .nodes
            .get(target.index())
            .and_then(|n| n.as_ref())
            .expect("elem_name called on invalid node");
        let name_ptr: *const QualName = match &node.data {
            NodeData::Element { name, .. } => name as *const QualName,
            _ => panic!("elem_name called on non-element"),
        };
        let ref_guard = Ref::map(borrow, |_| &());
        ObscuraElemName {
            _ref: ref_guard,
            name: name_ptr,
        }
    }

    fn create_element(
        &self,
        name: QualName,
        attrs: Vec<HtmlAttribute>,
        flags: ElementFlags,
    ) -> NodeId {
        let converted_attrs: Vec<Attribute> = attrs
            .into_iter()
            .map(|a| Attribute {
                name: a.name,
                value: a.value.to_string(),
            })
            .collect();

        let id = self.new_node(NodeData::Element {
            name: name.clone(),
            attrs: converted_attrs,
            template_contents: None,
            mathml_annotation_xml_integration_point: flags.mathml_annotation_xml_integration_point,
        });

        if flags.template {
            let template_doc = self.new_node(NodeData::Document);
            self.with_node_mut(id, |node| {
                if let NodeData::Element {
                    template_contents, ..
                } = &mut node.data
                {
                    *template_contents = Some(template_doc);
                }
            });
        }

        id
    }

    fn create_comment(&self, text: StrTendril) -> NodeId {
        self.new_node(NodeData::Comment {
            contents: text.to_string(),
        })
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> NodeId {
        self.new_node(NodeData::ProcessingInstruction {
            target: target.to_string(),
            data: data.to_string(),
        })
    }

    fn append(&self, parent: &NodeId, child: NodeOrText<NodeId>) {
        match child {
            NodeOrText::AppendNode(node_id) => {
                self.append_child(*parent, node_id);
            }
            NodeOrText::AppendText(text) => {
                self.append_text(*parent, &text);
            }
        }
    }

    fn append_based_on_parent_node(
        &self,
        element: &NodeId,
        prev_element: &NodeId,
        child: NodeOrText<NodeId>,
    ) {
        let has_parent = self
            .with_node(*element, |n| n.parent.is_some())
            .unwrap_or(false);
        if has_parent {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        name: StrTendril,
        public_id: StrTendril,
        system_id: StrTendril,
    ) {
        let doctype = self.new_node(NodeData::Doctype {
            name: name.to_string(),
            public_id: public_id.to_string(),
            system_id: system_id.to_string(),
        });
        let doc = self.document();
        self.append_child(doc, doctype);
    }

    fn add_attrs_if_missing(&self, target: &NodeId, attrs: Vec<HtmlAttribute>) {
        self.with_node_mut(*target, |node| {
            if let NodeData::Element {
                attrs: existing, ..
            } = &mut node.data
            {
                for attr in attrs {
                    let dominated = existing.iter().any(|a| a.name == attr.name);
                    if !dominated {
                        existing.push(Attribute {
                            name: attr.name,
                            value: attr.value.to_string(),
                        });
                    }
                }
            }
        });
    }

    fn remove_from_parent(&self, target: &NodeId) {
        self.detach(*target);
    }

    fn reparent_children(&self, node: &NodeId, new_parent: &NodeId) {
        let children = self.children(*node);
        for child_id in children {
            self.append_child(*new_parent, child_id);
        }
    }

    fn append_before_sibling(&self, sibling: &NodeId, child: NodeOrText<NodeId>) {
        match child {
            NodeOrText::AppendNode(node_id) => {
                self.insert_before(*sibling, node_id);
            }
            NodeOrText::AppendText(text) => {
                let prev_text_id = {
                    let node = self.get_node(*sibling);
                    node.and_then(|n| n.prev_sibling).and_then(|prev_id| {
                        let prev = self.get_node(prev_id);
                        prev.and_then(|p| if p.is_text() { Some(prev_id) } else { None })
                    })
                };

                if let Some(prev_text_id) = prev_text_id {
                    self.with_node_mut(prev_text_id, |node| {
                        if let NodeData::Text { contents } = &mut node.data {
                            contents.push_str(&text);
                        }
                    });
                    return;
                }

                let text_id = self.new_node(NodeData::Text {
                    contents: text.to_string(),
                });
                self.insert_before(*sibling, text_id);
            }
        }
    }

    fn get_template_contents(&self, target: &NodeId) -> NodeId {
        self.with_node(*target, |n| match &n.data {
            NodeData::Element {
                template_contents, ..
            } => *template_contents,
            _ => None,
        })
        .flatten()
        .expect("get_template_contents called on non-template element")
    }

    fn same_node(&self, x: &NodeId, y: &NodeId) -> bool {
        x == y
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        // Only full quirks mode makes CSS class/id selectors case-insensitive;
        // limited-quirks behaves like no-quirks for selector matching.
        self.set_quirks(mode == QuirksMode::Quirks);
    }

    fn allow_declarative_shadow_roots(&self, intended_parent: &NodeId) -> bool {
        self.allows_declarative_shadow_roots()
            && is_valid_shadow_host(self, *intended_parent)
            && self.shadow_root(*intended_parent).is_none()
    }

    fn attach_declarative_shadow(
        &self,
        location: &NodeId,
        template: &NodeId,
        attrs: &[HtmlAttribute],
    ) -> bool {
        let mode = attrs.iter().find_map(|attr| {
            if attr.name.local.as_ref() != "shadowrootmode" {
                return None;
            }
            match attr.value.as_ref() {
                "open" => Some(ShadowRootMode::Open),
                "closed" => Some(ShadowRootMode::Closed),
                _ => None,
            }
        });
        let Some(mode) = mode else {
            return false;
        };
        let root = self
            .with_node(*template, |node| match &node.data {
                NodeData::Element {
                    template_contents, ..
                } => *template_contents,
                _ => None,
            })
            .flatten();
        let Some(root) = root else {
            return false;
        };
        if self.attach_shadow_root_node(*location, root, mode).is_err() {
            return false;
        }
        // The temporary template was never inserted on the successful path,
        // but create_element registered any `id` before attachment. Use the
        // DOM removal path so that stale template ids cannot escape through
        // document.getElementById; template contents are a separate fragment
        // and remain alive as the native root.
        self.remove_child(*template);
        true
    }

    fn is_mathml_annotation_xml_integration_point(&self, target: &NodeId) -> bool {
        self.with_node(*target, |n| match &n.data {
            NodeData::Element {
                mathml_annotation_xml_integration_point,
                ..
            } => *mathml_annotation_xml_integration_point,
            _ => false,
        })
        .unwrap_or(false)
    }
}

/// Why an incremental document parser returned control to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserYield {
    /// Every currently available input character was consumed.
    NeedInput,
    /// The parser reached the end tag of a parser-inserted HTML script.
    ///
    /// The caller must run or schedule the script as appropriate, then call
    /// [`StreamingDocumentParser::resume`] before parsing can continue.
    Script(NodeId),
    /// End-of-input processing completed and the final DOM is available.
    Finished,
}

/// Result of synchronously parsing markup written by the script at the
/// current parser insertion point.
///
/// Unlike [`ParserYield`], `Complete` does not mean that the document parser
/// reached EOF. It means only that the input supplied by one
/// `document.write()` call was consumed and that the parser was restored to
/// the pause of the script which made that call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserInsertionYield {
    /// The parser is not paused at the claimed calling script. Hosts use this
    /// to retain their post-parser `document.write()` compatibility path.
    NotActive,
    /// The written input was consumed and control belongs to the calling
    /// script again.
    Complete,
    /// Written input created another parser-inserted script. The JavaScript
    /// host must execute it synchronously and then call
    /// [`StreamingDocumentParser::resume_insertion_after_script`].
    Script(NodeId),
}

struct ParserInsertionFrame {
    calling_script: NodeId,
    suspended_input: Vec<StrTendril>,
    suspended_eof_requested: bool,
}

/// An HTML document parser which exposes html5ever's script-pause boundary.
///
/// html5ever's ordinary [`parse_html`] path deliberately resumes immediately
/// whenever the tree builder reports a script. A browser host instead needs to
/// stop there because a parser-blocking script can inspect or mutate the live
/// tree before any later source is tokenized. This wrapper retains the parser
/// and its input queue across calls and returns that boundary to the host.
pub struct StreamingDocumentParser {
    parser: Option<html5ever::driver::Parser<DomTree>>,
    paused_script: Option<NodeId>,
    insertion_stack: Vec<ParserInsertionFrame>,
    eof_requested: bool,
    output: Option<DomTree>,
}

impl StreamingDocumentParser {
    pub fn new() -> Self {
        use html5ever::{parse_document, ParseOpts};

        let tree = DomTree::new();
        tree.set_allow_declarative_shadow_roots(true);
        StreamingDocumentParser {
            parser: Some(parse_document(tree, ParseOpts::default())),
            paused_script: None,
            insertion_stack: Vec::new(),
            eof_requested: false,
            output: None,
        }
    }

    /// The live tree built so far.
    ///
    /// It remains available while the parser is paused, allowing the browser
    /// host to expose exactly the prefix which a parser-blocking script is
    /// allowed to observe.
    pub fn dom(&self) -> &DomTree {
        if let Some(parser) = &self.parser {
            &parser.tokenizer.sink.sink
        } else {
            self.output
                .as_ref()
                .expect("streaming parser has neither an active parser nor output")
        }
    }

    /// Append one decoded chunk to the document input stream.
    ///
    /// Input may arrive while a script is paused; it is buffered but is not
    /// tokenized until [`Self::resume`] is called.
    pub fn feed(&mut self, chunk: &str) -> ParserYield {
        if self.output.is_some() {
            return ParserYield::Finished;
        }
        assert!(
            !self.eof_requested,
            "cannot feed a streaming parser after end-of-input"
        );
        if !chunk.is_empty() {
            self.parser
                .as_ref()
                .expect("active streaming parser")
                .input_buffer
                .push_back(chunk.into());
        }
        if let Some(script) = self.paused_script {
            return ParserYield::Script(script);
        }
        self.drive()
    }

    /// Continue tokenization after the caller has handled a script pause.
    pub fn resume(&mut self) -> ParserYield {
        if self.output.is_some() {
            return ParserYield::Finished;
        }
        self.paused_script = None;
        self.drive()
    }

    /// Parse `html` at the insertion point of the currently running
    /// parser-inserted script.
    ///
    /// The unread primary response is temporarily removed from html5ever's
    /// queue, so synchronous parsing cannot expose source which follows the
    /// calling script. The tokenizer and tree builder themselves are *not*
    /// replaced: token state, the stack of open elements, foster parenting,
    /// and the live DOM are therefore shared with the primary parse. Once the
    /// supplied input is exhausted, the unread response and the caller's
    /// script pause are restored.
    ///
    /// A nested parser-inserted script is returned to the host. Calls made by
    /// that script may recursively enter this method; each level suspends only
    /// the input belonging to its caller.
    pub fn insert_at_script_pause(
        &mut self,
        calling_script: NodeId,
        html: &str,
    ) -> ParserInsertionYield {
        if self.output.is_some() || self.paused_script != Some(calling_script) {
            return ParserInsertionYield::NotActive;
        }

        let parser = self.parser.as_ref().expect("active streaming parser");
        let suspended_input = drain_input_queue(&parser.input_buffer);
        let suspended_eof_requested = std::mem::replace(&mut self.eof_requested, false);
        self.insertion_stack.push(ParserInsertionFrame {
            calling_script,
            suspended_input,
            suspended_eof_requested,
        });
        self.paused_script = None;
        if !html.is_empty() {
            parser.input_buffer.push_back(html.into());
        }
        let yielded = self.drive();
        self.finish_insertion_turn(yielded)
    }

    /// Continue written input after the host synchronously executed a nested
    /// parser-inserted script returned by [`Self::insert_at_script_pause`].
    pub fn resume_insertion_after_script(
        &mut self,
        completed_script: NodeId,
    ) -> ParserInsertionYield {
        if self.output.is_some()
            || self.insertion_stack.is_empty()
            || self.paused_script != Some(completed_script)
        {
            return ParserInsertionYield::NotActive;
        }
        self.paused_script = None;
        let yielded = self.drive();
        self.finish_insertion_turn(yielded)
    }

    /// Signal that no more decoded document input will arrive.
    ///
    /// This can itself return [`ParserYield::Script`]. In that case the caller
    /// handles the script and calls [`Self::resume`]; the parser remembers the
    /// EOF request and completes once all remaining pauses have been resumed.
    pub fn finish(&mut self) -> ParserYield {
        if self.output.is_some() {
            return ParserYield::Finished;
        }
        self.eof_requested = true;
        if let Some(script) = self.paused_script {
            return ParserYield::Script(script);
        }
        self.drive()
    }

    /// Take the final tree after [`ParserYield::Finished`] was observed.
    pub fn into_dom(self) -> Option<DomTree> {
        self.output
    }

    fn drive(&mut self) -> ParserYield {
        loop {
            let result = {
                let parser = self.parser.as_ref().expect("active streaming parser");
                parser.tokenizer.feed(&parser.input_buffer)
            };
            match result {
                TokenizerResult::Done if self.eof_requested => {
                    let parser = self.parser.take().expect("active streaming parser");
                    debug_assert!(parser.input_buffer.is_empty());
                    parser.tokenizer.end();
                    self.output = Some(parser.tokenizer.sink.sink);
                    return ParserYield::Finished;
                }
                TokenizerResult::Done => return ParserYield::NeedInput,
                TokenizerResult::Script(script) => {
                    self.paused_script = Some(script);
                    return ParserYield::Script(script);
                }
                // The byte-to-Unicode decoder which owns this parser already
                // selected the document encoding. Match html5ever's standard
                // high-level driver by treating an in-document indicator as
                // advisory and continuing with that established encoding.
                TokenizerResult::EncodingIndicator(_) => continue,
            }
        }
    }

    fn finish_insertion_turn(&mut self, yielded: ParserYield) -> ParserInsertionYield {
        match yielded {
            ParserYield::Script(script) => ParserInsertionYield::Script(script),
            ParserYield::NeedInput => {
                let frame = self
                    .insertion_stack
                    .pop()
                    .expect("document.write insertion frame disappeared");
                let parser = self.parser.as_ref().expect("active streaming parser");
                debug_assert!(parser.input_buffer.is_empty());
                for input in frame.suspended_input {
                    parser.input_buffer.push_back(input);
                }
                self.eof_requested = frame.suspended_eof_requested;
                self.paused_script = Some(frame.calling_script);
                ParserInsertionYield::Complete
            }
            // EOF is disabled while an insertion frame is active. Treat this
            // as inactive instead of allowing a malformed host call to resume
            // a finalized parser.
            ParserYield::Finished => ParserInsertionYield::NotActive,
        }
    }
}

fn drain_input_queue(queue: &markup5ever::buffer_queue::BufferQueue) -> Vec<StrTendril> {
    let mut input = Vec::new();
    while let Some(chunk) = queue.pop_front() {
        input.push(chunk);
    }
    input
}

impl Default for StreamingDocumentParser {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_html(html: &str) -> DomTree {
    let mut parser = StreamingDocumentParser::new();
    let mut state = parser.feed(html);
    loop {
        state = match state {
            ParserYield::NeedInput => parser.finish(),
            // The compatibility helper has no script host. Preserve its
            // historical behavior by resuming immediately after each pause.
            ParserYield::Script(_) => parser.resume(),
            ParserYield::Finished => break,
        };
    }
    parser
        .into_dom()
        .expect("finished streaming parser did not retain its DOM")
}

pub fn parse_fragment(html: &str) -> DomTree {
    let context_name = QualName::new(None, ns!(html), local_name!("body"));
    parse_fragment_with_context(html, context_name)
}

/// Parse an HTML fragment using the supplied context element.
///
/// The tree builder's insertion mode depends on this context. Treating every
/// `innerHTML` assignment as body content drops table-only elements such as a
/// top-level `<tr>` and mis-parses select/template fragments. Browsers instead
/// use the receiver element as the fragment parsing context.
pub fn parse_fragment_with_context(html: &str, context_name: QualName) -> DomTree {
    use html5ever::tendril::TendrilSink;
    use html5ever::{parse_fragment, ParseOpts};
    let tree = DomTree::new();
    // Obscura's fragment parser backs innerHTML in a scripting-enabled
    // document. html5ever 0.39 makes that context flag explicit; keeping it
    // true preserves browser parsing for context-sensitive content such as
    // <noscript>.
    parse_fragment(tree, ParseOpts::default(), context_name, vec![], true)
        .from_utf8()
        .one(html.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish_streaming(parser: &mut StreamingDocumentParser) {
        let mut state = parser.finish();
        loop {
            state = match state {
                ParserYield::Script(_) => parser.resume(),
                ParserYield::NeedInput => parser.finish(),
                ParserYield::Finished => return,
            };
        }
    }

    fn parse_html_one_shot(html: &str) -> DomTree {
        use html5ever::tendril::TendrilSink;
        use html5ever::{parse_document, ParseOpts};

        let tree = DomTree::new();
        tree.set_allow_declarative_shadow_roots(true);
        parse_document(tree, ParseOpts::default())
            .from_utf8()
            .one(html.as_bytes())
    }

    #[test]
    fn streaming_parser_pauses_before_parsing_source_after_a_script() {
        let mut parser = StreamingDocumentParser::new();
        let state = parser.feed(
            "<!doctype html><html><body><script id=gate>window.gate = true;</script>\
             <main id=after>after</main></body></html>",
        );
        let script = match state {
            ParserYield::Script(script) => script,
            other => panic!("expected a script pause, got {other:?}"),
        };

        assert_eq!(parser.dom().get_element_by_id("gate"), Some(script));
        assert_eq!(parser.dom().text_content(script), "window.gate = true;");
        assert!(
            parser.dom().get_element_by_id("after").is_none(),
            "source after the blocking script was parsed before resume"
        );

        assert_eq!(parser.resume(), ParserYield::NeedInput);
        assert!(parser.dom().get_element_by_id("after").is_some());
        assert_eq!(parser.finish(), ParserYield::Finished);
        assert!(parser.into_dom().is_some());
    }

    #[test]
    fn streaming_parser_keeps_tokenizer_state_across_chunks_and_pauses() {
        let mut parser = StreamingDocumentParser::new();
        assert_eq!(
            parser.feed("<!doctype html><html><body><scr"),
            ParserYield::NeedInput
        );
        assert_eq!(parser.feed("ipt id=first>one</scr"), ParserYield::NeedInput);

        let first = match parser.feed("ipt><div id=between>middle</div><script id=second>") {
            ParserYield::Script(script) => script,
            other => panic!("expected first script pause, got {other:?}"),
        };
        assert_eq!(parser.dom().get_element_by_id("first"), Some(first));
        assert!(parser.dom().get_element_by_id("between").is_none());

        // Network input may arrive while script execution has the tokenizer
        // paused. It must be buffered without making later DOM visible.
        assert_eq!(
            parser.feed("two</script><p id=tail>tail</p></body></html>"),
            ParserYield::Script(first)
        );
        assert!(parser.dom().get_element_by_id("tail").is_none());

        let second = match parser.resume() {
            ParserYield::Script(script) => script,
            other => panic!("expected second script pause, got {other:?}"),
        };
        assert_eq!(parser.dom().get_element_by_id("between").is_some(), true);
        assert_eq!(parser.dom().get_element_by_id("second"), Some(second));
        assert!(parser.dom().get_element_by_id("tail").is_none());

        assert_eq!(parser.resume(), ParserYield::NeedInput);
        assert!(parser.dom().get_element_by_id("tail").is_some());
        assert_eq!(parser.finish(), ParserYield::Finished);
    }

    #[test]
    fn document_write_uses_primary_tokenizer_and_suspends_source_tail() {
        let mut parser = StreamingDocumentParser::new();
        let outer = match parser.feed(
            "<!doctype html><html><body><script id=outer></script>\
             <script id=source-tail></script><div id=after-source></div></body></html>",
        ) {
            ParserYield::Script(script) => script,
            other => panic!("expected outer script pause, got {other:?}"),
        };

        let nested = match parser
            .insert_at_script_pause(outer, "<script id=nested></script><i id=after-written></i>")
        {
            ParserInsertionYield::Script(script) => script,
            other => panic!("expected written nested script, got {other:?}"),
        };
        assert_eq!(parser.dom().get_element_by_id("nested"), Some(nested));
        assert!(parser.dom().get_element_by_id("after-written").is_none());
        assert!(parser.dom().get_element_by_id("source-tail").is_none());

        assert_eq!(
            parser.insert_at_script_pause(nested, "<span id=nested-write></span>"),
            ParserInsertionYield::Complete,
        );
        assert!(parser.dom().get_element_by_id("nested-write").is_some());
        assert!(parser.dom().get_element_by_id("source-tail").is_none());

        assert_eq!(
            parser.resume_insertion_after_script(nested),
            ParserInsertionYield::Complete,
        );
        assert!(parser.dom().get_element_by_id("after-written").is_some());
        assert!(parser.dom().get_element_by_id("source-tail").is_none());

        let source_tail = match parser.resume() {
            ParserYield::Script(script) => script,
            other => panic!("expected original source script, got {other:?}"),
        };
        assert_eq!(
            parser.dom().get_element_by_id("source-tail"),
            Some(source_tail)
        );
        assert!(parser.dom().get_element_by_id("after-source").is_none());
        assert_eq!(parser.resume(), ParserYield::NeedInput);
        assert!(parser.dom().get_element_by_id("after-source").is_some());
    }

    #[test]
    fn document_write_preserves_pending_eof_and_token_state_between_calls() {
        let mut parser = StreamingDocumentParser::new();
        let writer = match parser.feed("<html><body><script id=writer></script>") {
            ParserYield::Script(script) => script,
            other => panic!("expected writer pause, got {other:?}"),
        };
        assert_eq!(parser.finish(), ParserYield::Script(writer));

        assert_eq!(
            parser.insert_at_script_pause(writer, "<spa"),
            ParserInsertionYield::Complete,
        );
        assert_eq!(
            parser.insert_at_script_pause(writer, "n id=split>ok</span>"),
            ParserInsertionYield::Complete,
        );
        assert!(parser.dom().get_element_by_id("split").is_some());
        assert_eq!(parser.resume(), ParserYield::Finished);
    }

    #[test]
    fn streaming_parser_matches_one_shot_html5ever_for_malformed_markup() {
        let html = concat!(
            "<!doctype html><title>broken</title><body><p id=one>alpha",
            "<div><b>beta<script>window.x = '<tag>';</script>",
            "<table><tr><td>cell<p>paragraph</table>tail</b>"
        );
        let expected = parse_html_one_shot(html);

        let mut parser = StreamingDocumentParser::new();
        for chunk in [
            "<!doctype html><title>bro",
            "ken</title><body><p id=one>alpha<div><b>beta<scr",
            "ipt>window.x = '<tag>';",
            "</script><table><tr><td>cell<p>paragraph</ta",
            "ble>tail</b>",
        ] {
            let mut state = parser.feed(chunk);
            while let ParserYield::Script(_) = state {
                state = parser.resume();
            }
            assert_eq!(state, ParserYield::NeedInput);
        }
        finish_streaming(&mut parser);
        let actual = parser.into_dom().expect("finished streaming DOM");

        assert_eq!(
            actual.outer_html(actual.document()),
            expected.outer_html(expected.document())
        );
        assert_eq!(actual.is_quirks(), expected.is_quirks());
    }

    #[test]
    fn test_parse_simple_html() {
        let tree = parse_html("<html><head></head><body><h1>Hello</h1></body></html>");
        assert!(tree.len() > 3);
        let text = tree.text_content(tree.document());
        assert!(text.contains("Hello"));
    }

    #[test]
    fn test_parse_with_attributes() {
        let tree = parse_html(r#"<div id="main" class="container">Text</div>"#);
        let main = tree.get_element_by_id("main");
        assert!(main.is_some());
        let node = tree.get_node(main.unwrap()).unwrap();
        assert_eq!(node.get_attribute("class"), Some("container"));
    }

    #[test]
    fn test_parse_nested_structure() {
        let tree = parse_html(
            r#"<html><body>
                <div id="outer">
                    <p id="para">Hello <strong>World</strong></p>
                    <ul>
                        <li>Item 1</li>
                        <li>Item 2</li>
                    </ul>
                </div>
            </body></html>"#,
        );

        let outer = tree.get_element_by_id("outer").unwrap();
        let text = tree.text_content(outer);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(text.contains("Item 1"));
        assert!(text.contains("Item 2"));
    }

    #[test]
    fn test_parse_malformed_html() {
        let tree = parse_html("<div><p>Unclosed paragraph<p>Another<div>Nested wrong</div>");
        assert!(tree.len() > 3);
        let text = tree.text_content(tree.document());
        assert!(text.contains("Unclosed paragraph"));
        assert!(text.contains("Another"));
    }

    #[test]
    fn test_parse_doctype() {
        let tree = parse_html("<!DOCTYPE html><html><body>Hello</body></html>");
        let first_child = tree.children(tree.document())[0];
        let node = tree.get_node(first_child).unwrap();
        assert!(matches!(node.data, NodeData::Doctype { .. }));
    }

    #[test]
    fn test_parse_fragment() {
        let tree = parse_fragment("<p>Hello</p><p>World</p>");
        let text = tree.text_content(tree.document());
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
    }

    #[test]
    fn test_parse_fragment_uses_table_context() {
        let context_name = QualName::new(None, ns!(html), local_name!("template"));
        let tree = parse_fragment_with_context("<tr><td>cell</td></tr>", context_name);
        let row = tree
            .query_selector("tr")
            .expect("valid selector")
            .expect("template context preserves the row");
        assert_eq!(tree.text_content(row), "cell");
    }

    fn element_children(tree: &DomTree, parent: NodeId) -> Vec<NodeId> {
        tree.children(parent)
            .into_iter()
            .filter(|child| tree.get_node(*child).is_some_and(|node| node.is_element()))
            .collect()
    }

    #[test]
    fn full_document_consumes_open_and_closed_declarative_shadow_templates() {
        let tree = parse_html(
            r#"<x-open id="open-host">
                 <template id="open-template" shadowrootmode="open">
                   <span id="open-content">open shadow</span>
                 </template>
                 <b id="open-light">open light</b>
               </x-open>
               <x-closed id="closed-host">
                 <template id="closed-template" shadowrootmode="closed">
                   <span id="closed-content">closed shadow</span>
                 </template>
                 <b id="closed-light">closed light</b>
               </x-closed>"#,
        );

        let open_host = tree.get_element_by_id("open-host").unwrap();
        let closed_host = tree.get_element_by_id("closed-host").unwrap();
        let open_light = tree.get_element_by_id("open-light").unwrap();
        let closed_light = tree.get_element_by_id("closed-light").unwrap();
        let open_root = tree.shadow_root(open_host).expect("open root attached");
        let closed_root = tree.shadow_root(closed_host).expect("closed root attached");

        assert_eq!(
            tree.shadow_root_info(open_root).unwrap().mode,
            ShadowRootMode::Open
        );
        assert_eq!(
            tree.shadow_root_info(closed_root).unwrap().mode,
            ShadowRootMode::Closed
        );
        assert_eq!(element_children(&tree, open_host), vec![open_light]);
        assert_eq!(element_children(&tree, closed_host), vec![closed_light]);
        assert!(tree.get_element_by_id("open-template").is_none());
        assert!(tree.get_element_by_id("closed-template").is_none());
        assert!(tree
            .query_selector_from(open_root, "#open-content")
            .unwrap()
            .is_some());
        assert!(tree
            .query_selector_from(closed_root, "#closed-content")
            .unwrap()
            .is_some());
        assert!(
            tree.get_element_by_id("open-content").is_none()
                && tree.get_element_by_id("closed-content").is_none(),
            "document id lookup must not pierce either shadow mode"
        );
    }

    #[test]
    fn invalid_declarative_shadow_mode_remains_an_ordinary_template() {
        let tree = parse_html(
            r#"<x-card id="host"><template id="invalid" shadowrootmode="Open"><span id="inside"></span></template></x-card>
               <button id="invalid-host"><template id="invalid-host-template" shadowrootmode="open"><i id="invalid-host-content"></i></template></button>"#,
        );
        let host = tree.get_element_by_id("host").unwrap();
        let template = tree.get_element_by_id("invalid").unwrap();
        let contents = tree.template_contents(template).unwrap();
        let inside = tree.get_element_by_id("inside").unwrap();

        assert_eq!(tree.shadow_root(host), None);
        assert_eq!(element_children(&tree, host), vec![template]);
        assert_eq!(element_children(&tree, contents), vec![inside]);

        let invalid_host = tree.get_element_by_id("invalid-host").unwrap();
        let invalid_host_template = tree.get_element_by_id("invalid-host-template").unwrap();
        assert_eq!(tree.shadow_root(invalid_host), None);
        assert_eq!(
            element_children(&tree, invalid_host),
            vec![invalid_host_template],
            "an HTML element outside the valid-shadow-host allowlist stays inert"
        );
    }

    #[test]
    fn duplicate_declarative_shadow_root_falls_back_to_an_inert_template() {
        let tree = parse_html(
            r#"<x-card id="host">
                 <template shadowrootmode="open"><span id="first"></span></template>
                 <template id="duplicate" shadowrootmode="closed"><span id="second"></span></template>
                 <b id="light"></b>
               </x-card>"#,
        );
        let host = tree.get_element_by_id("host").unwrap();
        let light = tree.get_element_by_id("light").unwrap();
        let duplicate = tree.get_element_by_id("duplicate").unwrap();
        let duplicate_contents = tree.template_contents(duplicate).unwrap();
        let second = tree.get_element_by_id("second").unwrap();
        let root = tree.shadow_root(host).unwrap();

        assert_eq!(
            tree.shadow_root_info(root).unwrap().mode,
            ShadowRootMode::Open
        );
        assert!(tree.query_selector_from(root, "#first").unwrap().is_some());
        assert_eq!(element_children(&tree, host), vec![duplicate, light]);
        assert_eq!(element_children(&tree, duplicate_contents), vec![second]);
    }

    #[test]
    fn nested_declarative_shadow_roots_keep_distinct_tree_scopes() {
        let tree = parse_html(
            r#"<x-outer id="outer-host">
                 <template shadowrootmode="open">
                   <x-inner id="inner-host">
                     <template shadowrootmode="closed"><i id="inner-shadow"></i></template>
                     <b id="inner-light"></b>
                   </x-inner>
                 </template>
               </x-outer>"#,
        );
        let outer_host = tree.get_element_by_id("outer-host").unwrap();
        let outer_root = tree.shadow_root(outer_host).unwrap();
        let inner_host = tree
            .query_selector_from(outer_root, "#inner-host")
            .unwrap()
            .unwrap();
        let inner_root = tree.shadow_root(inner_host).unwrap();

        assert_eq!(tree.containing_shadow_root(inner_host), Some(outer_root));
        assert_eq!(
            tree.shadow_root_info(inner_root).unwrap().mode,
            ShadowRootMode::Closed
        );
        assert!(
            tree.query_selector_from(outer_root, "#inner-shadow")
                .unwrap()
                .is_none(),
            "an outer-tree query must not pierce a nested root"
        );
        assert!(tree
            .query_selector_from(inner_root, "#inner-shadow")
            .unwrap()
            .is_some());
        assert!(tree
            .query_selector_from(outer_root, "#inner-light")
            .unwrap()
            .is_some());
    }

    #[test]
    fn fragment_parsing_keeps_declarative_shadow_templates_inert() {
        let tree = parse_fragment_with_context(
            r#"<template id="shadow" shadowrootmode="open"><span id="inside"></span></template>"#,
            QualName::new(None, ns!(html), LocalName::from("x-card")),
        );
        let template = tree.get_element_by_id("shadow").unwrap();
        let contents = tree.template_contents(template).unwrap();
        let inside = tree.get_element_by_id("inside").unwrap();

        assert!(!tree.allows_declarative_shadow_roots());
        assert_eq!(element_children(&tree, contents), vec![inside]);
        assert!(tree.containing_shadow_root(inside).is_none());
    }

    #[test]
    fn ordinary_template_parsing_is_unchanged() {
        let tree = parse_html(
            r#"<div id="host">
                 <template id="ordinary"><span id="inside">content</span></template>
                 <span id="outside">light</span>
               </div>"#,
        );

        let host = tree.get_element_by_id("host").unwrap();
        let template = tree.get_element_by_id("ordinary").unwrap();
        let contents = tree.template_contents(template).unwrap();
        let inside = tree.get_element_by_id("inside").unwrap();
        let outside = tree.get_element_by_id("outside").unwrap();
        let element_children = |parent| {
            tree.children(parent)
                .into_iter()
                .filter(|child| tree.get_node(*child).is_some_and(|node| node.is_element()))
                .collect::<Vec<_>>()
        };

        assert_eq!(element_children(host), vec![template, outside]);
        assert!(tree.children(template).is_empty());
        assert_eq!(element_children(contents), vec![inside]);
        assert_eq!(tree.get_node(inside).unwrap().parent, Some(contents));
    }

    #[test]
    fn dormant_tree_sink_hook_reuses_the_template_contents_identity() {
        let tree = DomTree::new();
        let host = tree.new_node(NodeData::Element {
            name: QualName::new(None, ns!(html), LocalName::from("x-card")),
            attrs: vec![],
            template_contents: None,
            mathml_annotation_xml_integration_point: false,
        });
        tree.append_child(tree.document(), host);
        let contents = tree.new_node(NodeData::Document);
        let template = tree.new_node(NodeData::Element {
            name: QualName::new(None, ns!(html), local_name!("template")),
            attrs: vec![],
            template_contents: Some(contents),
            mathml_annotation_xml_integration_point: false,
        });
        tree.append_child(host, template);
        let attrs = vec![HtmlAttribute {
            name: QualName::new(
                None,
                Namespace::default(),
                LocalName::from("shadowrootmode"),
            ),
            value: StrTendril::from("closed"),
        }];

        assert!(!TreeSink::allow_declarative_shadow_roots(&tree, &host));
        assert!(TreeSink::attach_declarative_shadow(
            &tree, &host, &template, &attrs,
        ));
        assert_eq!(tree.shadow_root(host), Some(contents));
        assert!(tree.children(host).is_empty());
        assert_eq!(tree.get_node(template).unwrap().parent, None);
        assert_eq!(
            tree.shadow_root_info(contents).unwrap().mode,
            ShadowRootMode::Closed
        );
    }
}
