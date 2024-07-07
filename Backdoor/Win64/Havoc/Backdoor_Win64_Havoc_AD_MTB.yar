
rule Backdoor_Win64_Havoc_AD_MTB{
	meta:
		description = "Backdoor:Win64/Havoc.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {41 83 e9 20 6b c0 21 45 0f b6 c9 49 ff c2 44 01 c8 90 13 45 8a 0a 85 d2 75 06 45 84 c9 90 13 41 80 f9 60 90 13 6b c0 21 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}