
rule Worm_Win32_Autorun_NR{
	meta:
		description = "Worm:Win32/Autorun.NR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 55 0c 8a 1e 8a 04 39 02 d1 32 da 32 c2 88 1c 39 88 06 41 4e 3b 4d 08 } //2
		$a_03_1 = {3c 61 74 1d 3c 62 74 19 8d 45 fc 50 ff 15 90 01 03 00 83 f8 02 75 0a 90 00 } //1
		$a_01_2 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}