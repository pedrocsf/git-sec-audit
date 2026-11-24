from data.git.mailmap_author_normalizer import MailmapAuthorNormalizer
from domain.entities.author import Author


def test_same_email_case_insensitive_unified():
    normalizer = MailmapAuthorNormalizer()
    first = normalizer.normalize(Author("Bob", "bob@x.com"))
    second = normalizer.normalize(Author("Robert", "BOB@X.com"))
    assert second == first


def test_same_name_merged_when_enabled():
    normalizer = MailmapAuthorNormalizer(merge_by_name=True)
    first = normalizer.normalize(Author("Ana Silva", "a@x.com"))
    second = normalizer.normalize(Author("ana silva", "b@y.com"))
    assert second == first


def test_same_name_kept_apart_when_disabled():
    normalizer = MailmapAuthorNormalizer(merge_by_name=False)
    first = normalizer.normalize(Author("Ana", "a@x.com"))
    second = normalizer.normalize(Author("Ana", "b@y.com"))
    assert first != second


def test_distinct_authors_unchanged():
    normalizer = MailmapAuthorNormalizer()
    author = Author("Zed", "z@x.com")
    assert normalizer.normalize(author) == author
