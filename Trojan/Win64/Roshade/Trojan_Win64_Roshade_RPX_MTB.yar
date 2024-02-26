
rule Trojan_Win64_Roshade_RPX_MTB{
	meta:
		description = "Trojan:Win64/Roshade.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 48 8b 1d dc 48 03 00 48 8b 70 08 31 ed 4c 8b 25 3f c3 03 00 eb 16 0f 1f 44 00 00 48 39 c6 0f 84 1f 02 00 00 b9 e8 03 00 00 41 ff d4 } //00 00 
	condition:
		any of ($a_*)
 
}