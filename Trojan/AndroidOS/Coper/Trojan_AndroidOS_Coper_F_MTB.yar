
rule Trojan_AndroidOS_Coper_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.F!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {f0 b5 03 af 4d f8 04 bd 23 ea e3 7c bc f1 00 0f 27 d0 d0 e9 41 45 ac f1 01 0c 01 34 e6 17 04 eb 16 66 26 f0 ff 06 a4 1b c0 f8 04 41 06 5d 35 44 ee 17 05 eb 16 66 26 f0 ff 06 ad 1b c0 f8 08 51 03 5d 46 5d 06 55 43 55 d0 e9 41 34 04 5d c3 5c 23 44 11 f8 01 4b db b2 c3 5c 63 40 02 f8 01 3b d4 e7 5d f8 04 bb f0 bd d0 b5 02 af 88 5c cc 5c 8c 54 c8 54 d0 bd 01 f0 5d bb 01 f0 5b bb 01 f0 59 bb 70 47 } //5
		$a_01_1 = {ad f8 4c 30 07 f8 71 0c 46 f6 6f 60 37 4b 32 4a 27 f8 73 0c 33 48 47 f8 7f 3c 18 23 45 f9 03 0a 47 f8 41 2c 12 92 2d 4a 47 f8 77 0c 47 f8 87 0c 20 68 11 92 2a 4a 2e 4b 10 92 2b 4a 2b 60 47 f8 7b 2c 47 f8 8b 2c 82 69 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}