from BeautifulSoup import BeautifulSoup

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
