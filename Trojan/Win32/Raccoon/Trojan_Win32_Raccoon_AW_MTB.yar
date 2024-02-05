
rule Trojan_Win32_Raccoon_AW_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.AW!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 02 00 00 00 8b 44 24 08 90 01 04 24 83 2c 24 02 8b 04 24 31 01 59 c2 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}