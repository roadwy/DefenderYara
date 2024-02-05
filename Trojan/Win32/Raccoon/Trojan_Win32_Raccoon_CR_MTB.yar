
rule Trojan_Win32_Raccoon_CR_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 85 18 fe ff ff 03 c3 89 45 f4 8b c3 c1 e8 05 89 45 f8 8b 85 08 fe ff ff 01 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}