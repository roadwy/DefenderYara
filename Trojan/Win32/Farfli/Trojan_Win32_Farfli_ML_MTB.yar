
rule Trojan_Win32_Farfli_ML_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ML!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 8b 73 04 8b 7c 24 1c 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 24 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c } //1
		$a_01_1 = {8b 4e 54 8b 74 24 3c 55 8b 7e 3c 03 cf 8b f8 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 40 8b 74 24 1c 56 51 8b 51 3c 03 c2 89 45 00 89 58 34 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}