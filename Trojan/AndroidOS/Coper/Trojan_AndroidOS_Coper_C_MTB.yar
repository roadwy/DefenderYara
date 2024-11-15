
rule Trojan_AndroidOS_Coper_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 f0 68 ee 05 46 20 68 a7 f1 4e 01 82 69 20 46 90 47 01 46 20 68 a7 f1 56 02 a7 f1 6b 03 d0 f8 84 60 20 46 b0 47 02 46 20 46 29 46 01 f0 52 ee 20 e0 a7 f1 7e 02 a7 f1 a5 03 20 46 a8 47 02 46 20 46 31 46 01 f0 46 ee 05 46 20 68 82 69 4a a9 20 46 90 47 01 46 20 68 a7 f1 e3 03 d0 f8 78 61 48 aa 20 46 b0 47 02 46 20 68 29 46 } //1
		$a_01_1 = {10 70 46 f2 61 42 27 f8 23 2c 3f 4a 47 f8 27 2c 3f 4a 47 f8 2b 2c 34 a2 62 f9 cf 0a 14 22 43 f9 02 0a 64 22 1a 80 34 a3 63 f9 cf 0a 1e 23 45 f9 03 0a 43 f6 64 33 28 70 55 46 ad f8 4c 30 07 f8 71 0c 46 f6 6f 60 37 4b 32 4a 27 f8 73 0c 33 48 47 f8 7f 3c 18 23 45 f9 03 0a 47 f8 41 2c 12 92 2d 4a 47 f8 77 0c 47 f8 87 0c 20 68 11 92 2a 4a 2e 4b 10 92 2b 4a 2b 60 47 f8 7b 2c 47 f8 8b 2c 82 69 20 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}