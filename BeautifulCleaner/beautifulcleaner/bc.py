import BeautifulSoup
import defs

import re
import urlparse

# import xml.etree.cElementTree as etree
# from xml.etree.cElementTree import fromstring, tostring

__all__ = ['clean_html', 'clean', 'Cleaner']

# Look at http://code.sixapart.com/trac/livejournal/browser/trunk/cgi-bin/cleanhtml.pl
#   Particularly the CSS cleaning; most of the tag cleaning is integrated now
# I have multiple kinds of schemes searched; but should schemes be
#   whitelisted instead?
# max height?
# remove images?  Also in CSS?  background attribute?
# Some way to whitelist object, iframe, etc (e.g., if you want to
#   allow *just* embedded YouTube movies)
# Log what was deleted and why?
# style="behavior: ..." might be bad in IE?
# Should we have something for just <meta http-equiv>?  That's the worst of the
#   metas.
# UTF-7 detections?  Example:
#     <HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-
#   you don't always have to have the charset set, if the page has no charset
#   and there's UTF7-like code in it.
# Look at these tests: http://htmlpurifier.org/live/smoketests/xssAttacks.php


# This is an IE-specific construct you can have in a stylesheet to
# run some Javascript:
_css_javascript_re = re.compile(
    r'expression\s*\(.*?\)', re.S|re.I)

_css_url_re = re.compile(r'url\((.*?)\)', re.I)
_archive_re = re.compile(r'[^ ]+')

# Do I have to worry about @\nimport?
_css_import_re = re.compile(
    r'@\s*import', re.I)

# All kinds of schemes besides just javascript: that can cause
# execution:
_javascript_scheme_re = re.compile(
    r'\s*(?:javascript|jscript|livescript|vbscript|about|mocha):', re.I)
_substitute_whitespace = re.compile(r'\s+').sub
# FIXME: should data: be blocked?

# FIXME: check against: http://msdn2.microsoft.com/en-us/library/ms537512.aspx
_conditional_comment_re = re.compile(
    r'\[if[\s\n\r]+.*?][\s\n\r]*>', re.I|re.S)

# _find_styled_elements = etree.XPath(
#     "descendant-or-self::*[@style]")

# _find_external_links = etree.XPath(
#     "descendant-or-self::a[normalize-space(@href) and substring(normalize-space(@href),1,1) != '#']")

def removeElement(el):
    parent = el.parent
    while el.contents:
        item = el.contents[0]
        parent.insert(parent.contents.index(el), item)
    el.extract()


class Cleaner(object):
    """
    Instances cleans the document of each of the possible offending
    elements.  The cleaning is controlled by attributes; you can
    override attributes in a subclass, or set them in the constructor.

    ``scripts``:
        Removes any ``<script>`` tags.

    ``javascript``:
        Removes any Javascript, like an ``onclick`` attribute.

    ``comments``:
        Removes any comments.

    ``style``:
        Removes any style tags or attributes.

    ``links``:
        Removes any ``<link>`` tags

    ``meta``:
        Removes any ``<meta>`` tags

    ``page_structure``:
        Structural parts of a page: ``<head>``, ``<html>``, ``<title>``.

    ``processing_instructions``:
        Removes any processing instructions.

    ``embedded``:
        Removes any embedded objects (flash, iframes)

    ``frames``:
        Removes any frame-related tags

    ``forms``:
        Removes any form tags

    ``annoying_tags``:
        Tags that aren't *wrong*, but are annoying.  ``<blink>`` and ``<marque>``

    ``remove_tags``:
        A list of tags to remove.

    ``allow_tags``:
        A list of tags to include (default include all).

    ``remove_unknown_tags``:
        Remove any tags that aren't standard parts of HTML.

    ``safe_attrs_only``:
        If true, only include 'safe' attributes (specifically the list
        from `feedparser
        <http://feedparser.org/docs/html-sanitization.html>`_).

    ``add_nofollow``:
        If true, then any <a> tags will have ``rel="nofollow"`` added to them.

    ``host_whitelist``:
        A list or set of hosts that you can use for embedded content
        (for content like ``<object>``, ``<link rel="stylesheet">``, etc).
        You can also implement/override the method
        ``allow_embedded_url(el, url)`` or ``allow_element(el)`` to
        implement more complex rules for what can be embedded.
        Anything that passes this test will be shown, regardless of
        the value of (for instance) ``embedded``.

        Note that this parameter might not work as intended if you do not
        make the links absolute before doing the cleaning.

    ``whitelist_tags``:
        A set of tags that can be included with ``host_whitelist``.
        The default is ``iframe`` and ``embed``; you may wish to
        include other tags like ``script``, or you may want to
        implement ``allow_embedded_url`` for more control.  Set to None to
        include all tags.

    This modifies the document *in place*.
    """

    scripts = True
    javascript = True
    comments = True
    style = False
    links = True
    meta = True
    page_structure = True
    processing_instructions = True
    embedded = True
    frames = True
    forms = True
    annoying_tags = True
    remove_tags = None
    allow_tags = None
    remove_unknown_tags = True
    safe_attrs_only = True
    add_nofollow = False
    host_whitelist = ()
    whitelist_tags = set(['iframe', 'embed'])

    def __init__(self, **kw):
        for name, value in kw.items():
            if not hasattr(self, name):
                raise TypeError(
                    "Unknown parameter: %s=%r" % (name, value))
            setattr(self, name, value)

    # Used to lookup the primary URL for a given tag that is up for
    # removal:
    _tag_link_attrs = dict(
        script='src',
        link='href',
        # From: http://java.sun.com/j2se/1.4.2/docs/guide/misc/applet.html
        # From what I can tell, both attributes can contain a link:
        applet=['code', 'object'],
        iframe='src',
        embed='src',
        layer='src',
        # FIXME: there doesn't really seem like a general way to figure out what
        # links an <object> tag uses; links often go in <param> tags with values
        # that we don't really know.  You'd have to have knowledge about specific
        # kinds of plugins (probably keyed off classid), and match against those.
        ##object=?,
        # FIXME: not looking at the action currently, because it is more complex
        # than than -- if you keep the form, you should keep the form controls.
        ##form='action',
        a='href',
        )

    def __call__(self, doc):
        """
        Cleans the document.
        """
        # if hasattr(doc, 'getroot'):
        #     # ElementTree instance, instead of an element
        #     doc = doc.getroot()
        # Normalize a case that IE treats <image> like <img>, and that
        # can confuse either this step or later steps.
        for el in doc.findAll('image'):
            el.isSelfClosing=True
            el.name = u'img'
        if not self.comments:
            # Of course, if we were going to kill comments anyway, we don't
            # need to worry about this
            self.kill_conditional_comments(doc)
        kill_tags = set()
        remove_tags = set(self.remove_tags or ())
        if self.allow_tags:
            allow_tags = set(self.allow_tags)
        else:
            allow_tags = set()
        if self.scripts:
            kill_tags.add('script')
        if self.safe_attrs_only:
            safe_attrs = set(defs.safe_attrs)
            for el in doc.findAll():
                attrib = dict(el.attrs)
                for aname in attrib.keys():
                    if aname not in safe_attrs:
                        del el[aname]
        if self.javascript:
            if not self.safe_attrs_only:
                # safe_attrs handles events attributes itself
                for el in doc.findAll():
                    attrib = dict(el.attrs)
                    for aname in attrib.keys():
                        if aname.startswith('on'):
                            del el[aname]
            self.rewrite_links(doc, self._remove_javascript_link)
            if not self.style:
                # If we're deleting style then we don't have to remove JS links
                # from styles, otherwise...
                for el in doc.findAll(style=True):
                    old = el['style']
                    new = _css_javascript_re.sub('', old)
                    new = _css_import_re.sub('', old)
                    if self._has_sneaky_javascript(new):
                        # Something tricky is going on...
                        del el['style']
                    elif new != old:
                        el['style'] = new
                for el in doc.findAll('style'):
                    if dict(el.attrs).get('type', '').lower().strip() == 'text/javascript':
                        el.extract()
                        continue
                    old = el.string or ''
                    new = _css_javascript_re.sub('', old)
                    # The imported CSS can do anything; we just can't allow:
                    new = _css_import_re.sub('', old)
                    if self._has_sneaky_javascript(new):
                        # Something tricky is going on...
                        el.contents[0].replaceWith('/* deleted */')
                    elif new != old:
                        el.contents[0].replaceWith(new)
        if self.comments or self.processing_instructions:
            # FIXME: why either?  I feel like there's some obscure reason
            # because you can put PIs in comments...?  But I've already
            # forgotten it
            kill_tags.add(BeautifulSoup.Comment)
        if self.processing_instructions:
            kill_tags.add(BeautifulSoup.ProcessingInstruction)
        if self.style:
            kill_tags.add('style')
            for el in doc.findAll(style=True):
                del el['style']
        if self.links:
            kill_tags.add('link')
        elif self.style or self.javascript:
            # We must get rid of included stylesheets if Javascript is not
            # allowed, as you can put Javascript in them
            for el in doc.findAll('link'):
                if 'stylesheet' in el.get('rel', '').lower():
                    # Note this kills alternate stylesheets as well
                    el.extract()
        if self.meta:
            kill_tags.add('meta')
        if self.page_structure:
            remove_tags.update(('head', 'html', 'title', 'body'))
        if self.embedded:
            # FIXME: is <layer> really embedded?
            # We should get rid of any <param> tags not inside <applet>;
            # These are not really valid anyway.
            for el in doc.findAll('param'):
                found_parent = False
                parent = el.parent
                while parent is not None and parent.name not in ('applet', 'object'):
                    parent = parent.parent
                if parent is None:
                    el.extract()
            kill_tags.update(('applet',))
            # The alternate contents that are in an iframe are a good fallback:
            remove_tags.update(('iframe', 'embed', 'layer', 'object', 'param'))
            # print remove_tags
            # print kill_tags
        if self.frames:
            # FIXME: ideally we should look at the frame links, but
            # generally frames don't mix properly with an HTML
            # fragment anyway.
            kill_tags.update(defs.frame_tags)
        if self.forms:
            remove_tags.add('form')
            kill_tags.update(('button', 'input', 'select', 'textarea'))
        if self.annoying_tags:
            remove_tags.update(('blink', 'marque'))

        _remove = []
        _kill = []
        for el in doc.findAll():
            # print el.name
            if el.name in kill_tags:
                # print "killing %s" % el
                if self.allow_element(el):
                    continue
                _kill.append(el)
            elif el.name in remove_tags:
                # print "removing %s" % el
                if self.allow_element(el):
                    continue
                _remove.append(el)
        if BeautifulSoup.Comment in kill_tags:
            for el in doc.findAll(text=lambda text:isinstance(text, BeautifulSoup.Comment)):
                _kill.append(el)
        if BeautifulSoup.ProcessingInstruction in kill_tags:
            for el in doc.findAll(text=lambda text:isinstance(text, BeautifulSoup.ProcessingInstruction)):
                _kill.append(el)
        if BeautifulSoup.Comment in remove_tags:
            for el in doc.findAll(text=lambda text:isinstance(text, BeautifulSoup.Comment)):
                _remove.append(el)
        if BeautifulSoup.ProcessingInstruction in remove_tags:
            for el in doc.findAll(text=lambda text:isinstance(text, BeautifulSoup.ProcessingInstruction)):
                _remove.append(el)
        # I don't think this is needed for BeautifulSoup
        # if _remove and _remove[0] == doc:
        #     # We have to drop the parent-most tag, which we can't
        #     # do.  Instead we'll rewrite it:
        #     el = _remove.pop(0)
        #     el.tag = 'div'
        #     el.attrib.clear()
        # elif _kill and _kill[0] == doc:
        #     # We have to drop the parent-most element, which we can't
        #     # do.  Instead we'll clear it:
        #     el = _kill.pop(0)
        #     if el.tag != 'html':
        #         el.tag = 'div'
        #     el.clear()

        for el in _kill:
            el.extract()
        for el in _remove:
            removeElement(el)

        allow_tags = self.allow_tags
        if self.remove_unknown_tags:
            if allow_tags:
                raise ValueError(
                    "It does not make sense to pass in both allow_tags and remove_unknown_tags")
            allow_tags = set(defs.tags)
        if allow_tags:
            bad = []
            for el in doc.findAll():
                if el.name not in allow_tags:
                    bad.append(el)
            for el in bad:
                removeElement(el)
        if self.add_nofollow:
            for el in doc.findAll('a', href=re.compile('^(?!\s*#)')):
                if not self.allow_follow(el):
                    el['rel'] = 'nofollow'


    def iterlinks(self, doc):
        link_attrs = defs.link_attrs
        for el in doc.findAll():
            attribs = dict(el.attrs)
            if el.name != 'object':
                for attrib in link_attrs:
                    if attrib in attribs:
                        yield (el, attrib, el[attrib], 0)
            elif el.tag == 'object':
                codebase = None
                ## <object> tags have attributes that are relative to
                ## codebase
                if 'codebase' in attribs:
                    codebase = el['codebase']
                    yield (el, 'codebase', codebase, 0)
                for attrib in 'classid', 'data':
                    if attrib in attribs:
                        value = el[attrib]
                        if codebase is not None:
                            value = urlparse.urljoin(codebase, value)
                        yield (el, attrib, value, 0)
                if 'archive' in attribs:
                    for match in _archive_re.finditer(el['archive']):
                        value = match.group(0)
                        if codebase is not None:
                            value = urlparse.urljoin(codebase, value)
                        yield (el, 'archive', value, match.start())
            if el.tag == 'param':
                valuetype = el['valuetype'] or ''
                if valuetype.lower() == 'ref':
                    ## FIXME: while it's fine we *find* this link,
                    ## according to the spec we aren't supposed to
                    ## actually change the value, including resolving
                    ## it.  It can also still be a link, even if it
                    ## doesn't have a valuetype="ref" (which seems to be the norm)
                    ## http://www.w3.org/TR/html401/struct/objects.html#adef-valuetype
                    yield (el, 'value', el['value'], 0)
            if el.tag == 'style' and el.string:
                for match in _css_url_re.finditer(el.string):
                    yield (el, None, match.group(1), match.start(1))
                for match in _css_import_re.finditer(el.string):
                    yield (el, None, match.group(1), match.start(1))
            if 'style' in attribs:
                for match in _css_url_re.finditer(el['style']):
                    yield (el, 'style', match.group(1), match.start(1))

    def rewrite_links(self, doc, link_repl_func):
        for el, attrib, link, pos in self.iterlinks(doc):
            new_link = link_repl_func(link)
            if new_link == link:
                continue
            if new_link is None:
                # Remove the attribute or element content
                if attrib is None:
                    el.contents[0].replaceWith('')
                else:
                    del el[attrib]
                continue
            if attrib is None:
                new = el.string[:pos] + new_link + el.string[pos+len(link):]
                el.contents[0].replaceWith(new)
            else:
                cur = el[attrib]
                if not pos and len(cur) == len(link):
                    # Most common case
                    el[attrib] = new_link
                else:
                    new = cur[:pos] + new_link + cur[pos+len(link):]
                    el[attrib] = new

    def allow_follow(self, anchor):
        """
        Override to suppress rel="nofollow" on some anchors.
        """
        return False

    def allow_element(self, el):
        if el.name not in self._tag_link_attrs:
            return False
        attr = self._tag_link_attrs[el.name]
        if isinstance(attr, (list, tuple)):
            for one_attr in attr:
                url = el.get(one_attr)
                if not url:
                    return False
                if not self.allow_embedded_url(el, url):
                    return False
            return True
        else:
            url = el.get(attr)
            if not url:
                return False
            return self.allow_embedded_url(el, url)

    def allow_embedded_url(self, el, url):
        if (self.whitelist_tags is not None
            and el.name not in self.whitelist_tags):
            return False
        scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
        netloc = netloc.lower().split(':', 1)[0]
        if scheme not in ('http', 'https'):
            return False
        if netloc in self.host_whitelist:
            return True
        return False

    def kill_conditional_comments(self, doc):
        """
        IE conditional comments basically embed HTML that the parser
        doesn't normally see.  We can't allow anything like that, so
        we'll kill any comments that could be conditional.
        """
        bad = []
        for el in doc.findAll(text=lambda text:(isinstance(text, BeautifulSoup.Comment) and _conditional_comment_re.search(text))):
            bad.append(el)
        for el in bad:
            el.extract()

    # def _kill_elements(self, doc, condition, iterate=None):
    #     bad = []
    #     for el in doc.iter(iterate):
    #         if condition(el):
    #             bad.append(el)
    #     for el in bad:
    #         el.drop_tree()

    def _remove_javascript_link(self, link):
        # links like "j a v a s c r i p t:" might be interpreted in IE
        new = _substitute_whitespace('', link)
        if _javascript_scheme_re.search(new):
            # FIXME: should this be None to delete?
            return ''
        return link

    _substitute_comments = re.compile(r'/\*.*?\*/', re.S).sub

    def _has_sneaky_javascript(self, style):
        """
        Depending on the browser, stuff like ``e x p r e s s i o n(...)``
        can get interpreted, or ``expre/* stuff */ssion(...)``.  This
        checks for attempt to do stuff like this.

        Typically the response will be to kill the entire style; if you
        have just a bit of Javascript in the style another rule will catch
        that and remove only the Javascript from the style; this catches
        more sneaky attempts.
        """
        style = self._substitute_comments('', style)
        style = style.replace('\\', '')
        style = _substitute_whitespace('', style)
        style = style.lower()
        if 'javascript:' in style:
            return True
        if 'expression(' in style:
            return True
        return False

    def clean_html(self, html):
        doc = BeautifulSoup.BeautifulSoup(html)
        self(doc)
        return unicode(doc)
    # def clean_html(self, html):
    #     if isinstance(html, basestring):
    #         return_string = True
    #         doc = fromstring(html)
    #     else:
    #         return_string = False
    #         doc = copy.deepcopy(html)
    #     self(doc)
    #     if return_string:
    #         return tostring(doc)
    #     else:
    #         return doc

clean = Cleaner()
clean_html = clean.clean_html
