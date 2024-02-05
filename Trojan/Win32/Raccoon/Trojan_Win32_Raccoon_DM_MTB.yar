
rule Trojan_Win32_Raccoon_DM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b cf c1 e1 04 03 8d 10 fe ff ff 8b c7 c1 e8 05 03 85 08 fe ff ff 03 d7 33 ca 33 c8 } //00 00 
	condition:
		any of ($a_*)
 
}