from domain.entities.author import Author


class MailmapAuthorNormalizer:
    def __init__(self, merge_by_name: bool = True) -> None:
        self._merge_by_name = merge_by_name
        self._by_email: dict[str, Author] = {}
        self._by_name: dict[str, Author] = {}

    def normalize(self, author: Author) -> Author:
        email_key = author.email.lower()
        name_key = author.name.casefold()
        known = self._by_email.get(email_key) if email_key else None
        if known is None and self._merge_by_name:
            known = self._by_name.get(name_key)
        if known is None:
            known = author
        if email_key:
            self._by_email.setdefault(email_key, known)
        if self._merge_by_name:
            self._by_name.setdefault(name_key, known)
        return known
