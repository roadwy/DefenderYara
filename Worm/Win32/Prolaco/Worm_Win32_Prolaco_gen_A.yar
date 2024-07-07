
rule Worm_Win32_Prolaco_gen_A{
	meta:
		description = "Worm:Win32/Prolaco.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 10 8b ce 2b d6 8a 04 0a 32 44 24 0c 88 01 41 4f 75 f3 } //1
		$a_03_1 = {68 00 00 00 80 50 ff 15 90 01 04 8b f8 56 57 ff 15 90 01 04 3d 90 01 03 00 7e 12 3d 90 01 03 00 7d 0b 90 00 } //1
		$a_03_2 = {3c 41 88 45 90 01 01 74 25 3c 42 74 21 3c 61 74 1d 3c 62 74 19 8d 45 90 01 01 50 ff 15 90 01 04 83 f8 02 75 0a 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}