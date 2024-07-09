
rule Trojan_BAT_AveMaria_NEBJ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a } //5
		$a_03_1 = {07 16 07 8e 69 6f ?? 00 00 0a } //5
		$a_01_2 = {4d 4a 43 4b 56 4b 4c 55 49 4f 52 } //4 MJCKVKLUIOR
		$a_01_3 = {63 30 62 32 32 34 37 30 32 33 62 31 39 34 39 37 34 35 34 32 35 64 64 64 39 62 62 64 63 36 63 34 65 } //4 c0b2247023b1949745425ddd9bbdc6c4e
		$a_01_4 = {70 62 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 pbDebuggerPresent
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*1) >=19
 
}