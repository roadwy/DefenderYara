
rule Trojan_Win32_RedLine_RDEJ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c6 8b 44 24 14 c7 04 24 00 00 00 00 89 e1 51 57 50 56 6a ff ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}