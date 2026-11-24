from dataclasses import dataclass


@dataclass(frozen=True)
class Author:
    name: str
    email: str

    @property
    def identity(self) -> str:
        if self.email:
            return self.email.lower()
        return self.name.lower()
