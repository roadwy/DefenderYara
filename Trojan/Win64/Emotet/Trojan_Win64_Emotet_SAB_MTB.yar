
rule Trojan_Win64_Emotet_SAB_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 90 01 01 03 d0 41 90 01 02 41 90 01 02 6b d2 90 01 01 2b c2 48 90 01 02 48 90 01 06 8a 0c 01 43 90 01 03 41 90 01 02 49 90 01 02 48 90 01 03 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}