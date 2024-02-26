
rule Trojan_Win32_RedLine_EC_MTB{
	meta:
		description = "Trojan:Win32/RedLine.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f be 04 0a c1 e0 10 33 45 f8 89 45 f8 b9 01 00 00 00 c1 e1 00 8b 55 e0 0f be 04 0a c1 e0 08 33 45 f8 89 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}