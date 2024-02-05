
rule Trojan_Win64_Grandoreiro_psyG_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {b8 7d 45 35 54 33 d2 f7 75 0c 05 90 02 2f 33 d2 6a 50 59 f7 f1 83 fa 79 74 20 8b 45 10 8b 4d 10 49 89 4d 10 85 c0 74 12 8b 45 08 03 45 10 8b 4d 0c 03 4d 10 8a 09 88 08 eb b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}