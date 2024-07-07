
rule Worm_Win32_Nelboomro_B{
	meta:
		description = "Worm:Win32/Nelboomro.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 37 2f 47 49 85 c9 75 f7 } //1
		$a_01_1 = {e8 0c 00 00 00 68 6f 6c 61 7c 4e 6f 6d 62 72 65 00 ff 35 } //1
		$a_03_2 = {83 f8 02 0f 85 90 01 02 00 00 66 81 3b 41 3a 75 05 e9 90 00 } //1
		$a_01_3 = {7e 21 81 38 45 78 69 74 75 08 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}