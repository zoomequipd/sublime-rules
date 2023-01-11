rule SublimeTest {
   meta:
      author = "Sublime Security 2"
      description = "Used to test that Sublime Platform YARA signature support is working properly for dupes."

   strings:
      $test_string = "Sublime-Standard-Test-String-Dupes"

   condition:
      $test_string
}
