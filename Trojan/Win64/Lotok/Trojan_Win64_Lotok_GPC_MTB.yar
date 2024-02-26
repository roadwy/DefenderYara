
rule Trojan_Win64_Lotok_GPC_MTB{
	meta:
		description = "Trojan:Win64/Lotok.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {41 b9 00 30 00 00 48 8b 4c 24 50 48 03 df c7 44 24 20 40 00 00 00 44 8b 43 50 8b 53 34 ff 15 90 01 04 4c 8b f0 48 85 c0 90 00 } //05 00 
		$a_01_1 = {48 03 c6 4c 89 6c 24 20 44 8b 44 18 2c 8b 54 18 24 4c 03 c1 48 8b 4c 24 50 49 03 d6 44 8b 4c 18 28 } //00 00 
	condition:
		any of ($a_*)
 
}