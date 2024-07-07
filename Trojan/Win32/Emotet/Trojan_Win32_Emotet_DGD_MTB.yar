
rule Trojan_Win32_Emotet_DGD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 7f 0a 01 00 f7 f9 8d 4c 24 18 8a 9c 14 90 01 04 32 5d 00 e8 90 01 04 88 5d 00 90 00 } //1
		$a_81_1 = {48 71 79 31 7a 44 4a 46 7a 32 34 44 53 6f 6f 44 67 62 4d 5a 4c 59 66 58 45 68 71 78 33 52 32 58 49 64 33 68 44 4b 43 } //1 Hqy1zDJFz24DSooDgbMZLYfXEhqx3R2XId3hDKC
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}