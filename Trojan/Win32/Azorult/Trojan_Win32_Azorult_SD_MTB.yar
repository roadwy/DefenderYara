
rule Trojan_Win32_Azorult_SD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.SD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 3a 0d 03 00 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07 53 55 56 57 33 f6 e8 22 04 00 00 b9 49 f7 02 78 89 44 24 1c e8 14 04 00 00 b9 58 a4 53 e5 89 44 24 20 e8 06 04 00 00 b9 10 e1 8a c3 8b e8 e8 fa 03 00 00 b9 af b1 5c 94 89 44 24 2c e8 ec 03 00 00 b9 33 00 9e 95 89 44 24 30 e8 de 03 00 00 8b d8 8b 44 24 5c 8b 78 3c 03 f8 89 7c 24 10 81 3f 50 45 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}