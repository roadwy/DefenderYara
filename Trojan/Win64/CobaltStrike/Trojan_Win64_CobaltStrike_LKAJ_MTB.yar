
rule Trojan_Win64_CobaltStrike_LKAJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 89 f1 c1 e1 05 01 ce 01 c6 0f b7 02 48 83 c2 02 66 85 c0 75 e8 81 fe 36 af 17 51 } //00 00 
	condition:
		any of ($a_*)
 
}