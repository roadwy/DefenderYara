
rule Trojan_Win32_Amadey_AA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {83 f8 10 b9 90 01 04 a1 90 01 04 0f 43 ca 03 c1 3b f0 74 90 01 01 8b 45 90 01 01 8b 57 10 8a 0c 30 32 0e 88 4d f0 3b 57 14 73 90 01 01 83 7f 14 10 8d 42 01 89 47 10 8b c7 72 90 01 01 8b 07 88 0c 10 46 c6 44 10 01 00 a1 90 01 04 8b 15 90 01 04 eb 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}