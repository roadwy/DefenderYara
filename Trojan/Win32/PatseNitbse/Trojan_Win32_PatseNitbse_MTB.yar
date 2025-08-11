
rule Trojan_Win32_PatseNitbse_MTB{
	meta:
		description = "Trojan:Win32/PatseNitbse!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {44 00 4f 00 43 00 54 00 59 00 50 00 45 00 20 00 68 00 74 00 6d 00 6c 00 } //1 DOCTYPE html
		$a_00_2 = {50 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 } //1 Pastebin
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}