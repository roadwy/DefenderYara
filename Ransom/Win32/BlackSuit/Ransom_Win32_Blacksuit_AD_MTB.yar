
rule Ransom_Win32_Blacksuit_AD_MTB{
	meta:
		description = "Ransom:Win32/Blacksuit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 01 2d 01 04 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {8b c6 8d 0c 37 33 d2 46 f7 74 24 90 01 01 8a 82 90 01 04 32 04 0b 88 01 81 fe 90 01 02 00 00 72 90 00 } //100
		$a_01_2 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 62 00 6c 00 61 00 63 00 6b 00 73 00 75 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //100 readme.blacksuit.txt
		$a_01_3 = {42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 } //100 BEGIN RSA PUBLIC KEY
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100) >=301
 
}