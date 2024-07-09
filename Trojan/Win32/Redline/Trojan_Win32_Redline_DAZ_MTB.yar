
rule Trojan_Win32_Redline_DAZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 44 24 14 8b 44 24 20 01 44 24 14 81 3d [0-04] 79 09 00 00 75 } //1
		$a_03_1 = {8b 54 24 14 33 d7 31 54 24 0c 8b 44 24 0c 29 44 24 10 81 3d [0-04] 93 00 00 00 75 } //1
		$a_01_2 = {72 6f 66 69 76 75 6e 6f 6d 6f 74 6f 79 61 73 6f 79 69 6c 6f 6e 61 77 } //1 rofivunomotoyasoyilonaw
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}