
rule Trojan_Win32_ClickFix_BBC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 54 00 45 00 4d 00 50 00 2b 00 27 00 27 00 2b 00 } //1 $env:TEMP+''+
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}