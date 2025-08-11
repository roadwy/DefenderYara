
rule Trojan_Win32_ClickFix_DFG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DFG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 00 67 00 75 00 69 00 64 00 5d 00 3a 00 3a 00 4e 00 65 00 77 00 47 00 75 00 69 00 64 00 28 00 29 00 } //100 [guid]::NewGuid()
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //10 curl
		$a_00_2 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 2b 00 } //1 =$env:APPDATA+
		$a_00_3 = {3d 00 24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 2b 00 } //1 =$env:TEMP+
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=111
 
}