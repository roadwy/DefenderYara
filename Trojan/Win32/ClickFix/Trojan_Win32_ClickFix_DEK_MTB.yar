
rule Trojan_Win32_ClickFix_DEK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 67 00 75 00 69 00 64 00 5d 00 3a 00 3a 00 4e 00 65 00 77 00 47 00 75 00 69 00 64 00 28 00 29 00 2e 00 54 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 29 00 } //10 [guid]::NewGuid().ToString()
		$a_00_2 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 } //10 $env:TEMP
		$a_00_3 = {2d 00 4f 00 75 00 74 00 46 00 69 00 6c 00 65 00 20 00 24 00 } //10 -OutFile $
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}