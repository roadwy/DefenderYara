
rule Trojan_Win32_Raccoon_DR_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.DR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c1 8b 75 08 33 d2 f7 f7 8a 04 32 30 04 19 41 3b 4d 10 } //00 00 
	condition:
		any of ($a_*)
 
}