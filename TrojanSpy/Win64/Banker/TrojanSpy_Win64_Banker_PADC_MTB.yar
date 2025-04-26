
rule TrojanSpy_Win64_Banker_PADC_MTB{
	meta:
		description = "TrojanSpy:Win64/Banker.PADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 f1 78 3b f6 82 80 e2 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0 8b c2 d1 e8 44 8b c0 41 81 f0 78 3b f6 82 80 e2 01 44 0f 44 c0 41 8b c8 d1 e9 44 8b c9 41 81 f1 78 3b f6 82 41 80 e0 01 44 0f 44 c9 48 83 eb 01 0f 85 51 } //1
		$a_01_1 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 } //1 Elevation:Administrator!new:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}