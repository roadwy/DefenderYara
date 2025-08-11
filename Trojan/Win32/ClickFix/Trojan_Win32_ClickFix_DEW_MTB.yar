
rule Trojan_Win32_ClickFix_DEW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_00_0 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 2b 00 } //100 =$env:TEMP+
		$a_00_1 = {5b 00 67 00 75 00 69 00 64 00 5d 00 3a 00 3a 00 4e 00 65 00 77 00 47 00 75 00 69 00 64 00 28 00 29 00 } //10 [guid]::NewGuid()
		$a_00_2 = {5b 00 69 00 6f 00 2e 00 66 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 57 00 72 00 69 00 74 00 65 00 41 00 6c 00 6c 00 42 00 79 00 74 00 65 00 73 00 28 00 24 00 } //10 [io.file]::WriteAllBytes($
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=111
 
}