
rule Trojan_BAT_NanoCore_NEB_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 55 30 6c 4e 4b 4b 43 4f 6a 47 4f 53 63 43 6f 6a 59 } //01 00  qU0lNKKCOjGOScCojY
		$a_01_1 = {6f 78 4f 73 51 30 54 79 6d 55 47 41 6b 6d 33 4c 51 39 } //01 00  oxOsQ0TymUGAkm3LQ9
		$a_01_2 = {64 63 4e 45 73 58 74 43 66 59 35 71 48 39 35 66 65 6b } //01 00  dcNEsXtCfY5qH95fek
		$a_01_3 = {44 45 38 58 32 74 6d 4a 37 4b 32 62 46 33 77 67 62 47 55 } //01 00  DE8X2tmJ7K2bF3wgbGU
		$a_01_4 = {73 4b 48 75 42 76 46 34 61 } //01 00  sKHuBvF4a
		$a_01_5 = {47 35 65 6f 64 59 70 48 4f 4d 53 52 71 57 62 66 79 76 } //00 00  G5eodYpHOMSRqWbfyv
	condition:
		any of ($a_*)
 
}