
rule Virus_Win32_Ramnit_remnants{
	meta:
		description = "Virus:Win32/Ramnit!remnants,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 33 d2 b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 8b d9 f7 75 0c } //1
		$a_03_1 = {81 ef 00 00 01 00 81 ff 00 00 00 70 73 90 01 01 bf 00 00 00 00 90 00 } //1
		$a_03_2 = {8b f8 c6 07 2d 47 6a 04 57 ff b5 90 01 02 ff ff 8d 83 64 a7 01 20 ff d0 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}