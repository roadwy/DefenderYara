
rule Trojan_Win64_CobaltStrike_MW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 d8 48 69 f3 90 01 04 48 89 f1 48 c1 e9 90 01 01 48 c1 fe 90 01 01 01 ce c1 e6 90 01 01 8d 0c b6 29 cb 48 63 cb 42 0f b6 0c 01 32 0c 02 88 0c 07 48 ff c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_MW_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {29 e8 01 f8 01 c1 48 8d 05 90 01 04 44 29 c9 44 01 d1 41 01 cb 41 29 eb 41 01 fb 4d 63 db 42 32 14 18 48 8b 44 24 50 42 88 14 20 48 8b 44 24 30 48 39 44 24 40 4c 8d 60 01 0f 87 90 00 } //02 00 
		$a_01_1 = {41 42 50 4e 52 77 44 75 67 76 72 65 46 4b 4b 54 58 6d 43 41 66 } //02 00 
		$a_01_2 = {41 42 67 47 4d 62 55 45 50 64 63 61 72 62 } //00 00 
	condition:
		any of ($a_*)
 
}