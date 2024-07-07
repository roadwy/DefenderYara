
rule Virus_Win32_Expiro_gen_G{
	meta:
		description = "Virus:Win32/Expiro.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 6b 71 76 78 5f 2e 64 6c 6c 00 } //2
		$a_03_1 = {0f b7 45 fe 01 f0 0f be 10 0f b6 4d 90 01 01 31 ca 88 10 90 00 } //1
		$a_03_2 = {b9 0a 00 00 00 99 f7 f9 0f b6 14 15 90 01 04 8b 7d 90 01 01 31 d7 89 fa 8b 7d 90 01 01 88 17 66 ff 45 fe 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}