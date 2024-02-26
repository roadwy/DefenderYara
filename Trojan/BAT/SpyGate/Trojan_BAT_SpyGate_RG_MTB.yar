
rule Trojan_BAT_SpyGate_RG_MTB{
	meta:
		description = "Trojan:BAT/SpyGate.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 72 6f 6f 74 30 5c 44 65 73 6b 74 6f 70 5c d8 a7 d9 84 d8 a7 d8 ae d8 aa d8 b1 d8 a7 d9 82 5c 50 72 69 76 61 74 65 5c 73 65 6e 64 20 66 69 6c 65 20 6d 5c 53 65 72 76 65 72 5c 53 65 72 76 65 72 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 53 65 72 76 65 72 2e 70 64 62 } //01 00 
		$a_01_1 = {69 00 6e 00 66 00 6f 00 7c 00 7c 00 6d 00 79 00 49 00 44 00 7c 00 } //01 00  info||myID|
		$a_01_2 = {54 00 68 00 65 00 20 00 46 00 69 00 6c 00 65 00 20 00 48 00 61 00 73 00 20 00 52 00 75 00 6e 00 } //01 00  The File Has Run
		$a_01_3 = {61 00 76 00 67 00 6e 00 74 00 } //01 00  avgnt
		$a_01_4 = {41 00 76 00 69 00 72 00 61 00 } //00 00  Avira
	condition:
		any of ($a_*)
 
}