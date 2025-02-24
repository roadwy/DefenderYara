
rule Trojan_Win32_LummaC_HNAB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.HNAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 3b 85 d2 74 19 89 ce c1 e6 05 01 ce 01 d6 47 89 f1 39 fd 75 e8 } //2
		$a_01_1 = {8b 40 18 c3 31 c0 c3 cc 8b 4c 24 04 31 c0 85 c9 74 0f 8b 54 24 08 39 51 18 76 06 8b 41 0c 8b 04 90 c3 } //1
		$a_03_2 = {0f ad fe 89 fa d3 ea f6 c1 20 ?? ?? 89 d6 31 d2 31 d7 31 c6 81 cf 01 01 01 01 81 ce 01 01 01 01 57 56 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=3
 
}