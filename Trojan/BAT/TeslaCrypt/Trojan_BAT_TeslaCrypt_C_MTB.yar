
rule Trojan_BAT_TeslaCrypt_C_MTB{
	meta:
		description = "Trojan:BAT/TeslaCrypt.C!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 68 72 6f 64 69 74 65 2e 64 6c 6c } //01 00  Aphrodite.dll
		$a_01_1 = {46 72 69 65 64 72 69 63 68 } //01 00  Friedrich
		$a_01_2 = {73 65 74 5f 4b 65 79 00 73 65 74 5f 49 56 00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 57 72 69 74 65 00 43 6c 6f 73 65 00 54 6f 41 72 72 61 79 } //00 00  敳彴敋y敳彴噉䌀敲瑡䑥捥祲瑰牯圀楲整䌀潬敳吀䅯牲祡
		$a_01_3 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}