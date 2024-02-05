
rule Trojan_BAT_ClipBanker_AT_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00 
		$a_01_1 = {67 65 74 5f 49 73 41 6c 69 76 65 } //02 00 
		$a_01_2 = {4d 40 6f 55 43 43 2f 5f 49 33 50 33 3f 62 2f 70 5c 5b 2d 50 38 29 3b 49 38 22 2e 72 65 73 6f 75 72 63 65 73 } //02 00 
		$a_01_3 = {42 4e 47 7d 2f 49 39 68 36 78 7c 3e 5c 2a 7a 6a 39 35 75 24 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}