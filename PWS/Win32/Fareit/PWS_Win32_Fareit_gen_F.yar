
rule PWS_Win32_Fareit_gen_F{
	meta:
		description = "PWS:Win32/Fareit.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {88 5c 1e 04 8b c3 33 d2 f7 f1 03 d7 8a 02 88 84 1d 00 ff ff ff 8b c3 40 88 44 1e 05 8d 43 01 } //1
		$a_03_1 = {0f b7 12 c1 e2 02 03 c2 01 d8 8b 30 01 de eb ?? ff 45 } //1
		$a_01_2 = {bf cc cc cc 0c 8a 1e 46 80 fb 20 74 f8 b5 00 80 fb 2d 74 62 80 fb 2b 74 5f 80 fb 24 74 5f 80 fb 78 74 5a 80 fb 58 74 55 80 fb 30 75 13 8a 1e 46 80 fb 78 74 48 80 fb 58 74 43 84 db 74 20 eb 04 } //1
		$a_00_3 = {54 00 69 00 62 00 69 00 61 00 } //1 Tibia
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}