
rule Trojan_Win64_Convagent_CRHW_MTB{
	meta:
		description = "Trojan:Win64/Convagent.CRHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b9 04 00 00 00 41 b8 00 10 00 00 8b d6 48 8b cb ff 15 90 01 04 48 85 c0 74 20 4c 8d 4d 04 41 b8 04 01 00 00 8b d6 48 8b cb ff 15 90 01 04 85 c0 74 90 01 01 b8 01 00 00 00 eb 90 00 } //01 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 34 35 2e 32 30 34 2e 37 31 2e 31 33 33 2f 90 02 1f 2e 65 78 65 90 00 } //01 00 
		$a_03_2 = {68 74 74 70 3a 2f 2f 34 35 2e 32 30 34 2e 37 31 2e 31 33 33 2f 90 02 1f 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}