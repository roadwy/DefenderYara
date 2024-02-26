
rule Trojan_Win32_Raccoon_RPY_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f f7 d6 03 f3 c1 ce 08 f7 d2 03 c4 4f 40 } //00 00 
	condition:
		any of ($a_*)
 
}