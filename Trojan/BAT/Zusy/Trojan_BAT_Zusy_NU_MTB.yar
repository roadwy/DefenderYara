
rule Trojan_BAT_Zusy_NU_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5d 06 06 1f 1f 5f 64 06 06 1f 1f 5f 64 5b 5d 16 5f 06 06 20 33 97 10 92 06 5c 5a 66 5b 66 41 5b 00 00 00 20 a3 a9 16 b0 06 06 20 79 56 e9 4f 61 61 58 67 } //2
		$a_01_1 = {06 1f 16 63 66 58 06 65 1f 1f 5f 63 20 a9 e9 86 02 58 67 0a 02 } //1
		$a_01_2 = {53 00 74 00 65 00 61 00 6c 00 31 00 2e 00 65 00 78 00 65 00 } //1 Steal1.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Zusy_NU_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 26 } //3
		$a_01_1 = {24 36 65 66 39 62 31 65 35 2d 33 30 64 34 2d 34 31 31 32 2d 62 61 39 37 2d 65 65 62 63 35 66 38 61 63 35 64 38 } //1 $6ef9b1e5-30d4-4112-ba97-eebc5f8ac5d8
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}