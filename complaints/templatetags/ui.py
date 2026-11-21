from django import template
from django.templatetags.static import static
from django.utils.html import format_html

register = template.Library()


@register.simple_tag
def icon(name, css=""):
    """Inline SVG icon from our self-hosted sprite: {% icon "house-fill" %}."""
    return format_html(
        '<svg class="icon {}" width="16" height="16" aria-hidden="true" focusable="false">'
        '<use href="{}#{}"></use></svg>',
        css, static("vendor/icons/sprite.svg"), name,
    )


@register.filter
def nice(value):
    """access_denied -> Access denied"""
    return str(value).replace("_", " ").capitalize()
