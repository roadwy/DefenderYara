
rule Trojan_Win32_Artoelo_BA{
	meta:
		description = "Trojan:Win32/Artoelo.BA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {3e 6e 75 6c 20 26 20 } //>nul &   1
		$a_80_1 = {5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c } //\windows\temp\  1
		$a_80_2 = {5c 5c 2e 5c 70 69 70 65 5c 6d 6f 76 65 } //\\.\pipe\move  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}