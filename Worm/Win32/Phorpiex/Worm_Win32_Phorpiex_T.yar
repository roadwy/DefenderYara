
rule Worm_Win32_Phorpiex_T{
	meta:
		description = "Worm:Win32/Phorpiex.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 c1 e8 10 25 ff 7f 00 00 25 03 00 00 80 79 05 48 83 c8 fc 40 8b 4c 84 90 01 01 51 8d 54 24 90 01 01 52 e9 90 00 } //2
		$a_03_1 = {83 c0 02 83 c1 02 84 d2 75 90 01 01 33 c0 eb 05 1b c0 83 d8 ff 85 c0 74 90 01 01 8d 4c 24 90 01 01 51 56 e8 90 00 } //1
		$a_01_2 = {25 73 5c 72 6d 72 66 25 69 25 69 25 69 25 69 2e 62 61 74 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}