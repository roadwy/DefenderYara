
rule Trojan_Win64_ClipBanker_L_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 89 d1 e8 90 01 03 00 48 89 44 24 28 49 8d 34 04 48 83 f8 0f 76 90 00 } //02 00 
		$a_01_1 = {5c 62 28 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 29 } //02 00  \b(0x[a-fA-F0-9]{40})
		$a_01_2 = {5c 62 28 28 5b 31 33 5d 7c 62 63 31 29 5b 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 31 2d 39 5d 7b 32 37 2c 33 34 7d 29 } //00 00  \b(([13]|bc1)[A-HJ-NP-Za-km-z1-9]{27,34})
	condition:
		any of ($a_*)
 
}