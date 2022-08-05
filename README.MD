# not-byfron

this is an attempt to replicate the "guarded pages" feature of riot vanguard/byfron. The dll encrypts the text section of a binary, afterwards installs an exception handler and sets the entire section to PAGE_NO_ACCESS. Now as soon as the execution moves to this binary, the exception handler gets triggered, decrypts the page in question, sets the DEP value and resumes execution. To prevent a completely decrypted text section the dll tracks all decrypted pages and renecrypts old, unused pages.
