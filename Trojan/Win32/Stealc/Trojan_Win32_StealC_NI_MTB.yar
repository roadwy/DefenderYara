
rule Trojan_Win32_StealC_NI_MTB{
	meta:
		description = "Trojan:Win32/StealC.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 69 77 75 67 75 6b 69 79 61 78 20 64 65 64 6f 6c 6f 6e 65 6d 61 79 6f 74 69 73 6f 72 75 70 20 67 65 77 75 79 61 79 75 70 6f 73 61 77 65 74 6f 73 65 73 6f 77 65 6c 75 6e 20 6b 69 70 75 6b 75 6e } //2 ciwugukiyax dedolonemayotisorup gewuyayuposawetosesowelun kipukun
		$a_81_1 = {74 75 7a 75 64 69 6e 75 79 6f 64 61 77 69 7a 20 78 69 76 69 7a 65 76 6f 62 69 6b 6f 74 75 6c 65 74 69 66 65 } //1 tuzudinuyodawiz xivizevobikotuletife
		$a_81_2 = {72 65 74 65 79 75 64 61 68 65 63 65 76 6f 79 61 63 61 64 } //1 reteyudahecevoyacad
		$a_81_3 = {79 65 67 69 6e 65 6a 69 70 61 72 61 74 75 64 65 66 61 66 20 62 6f 6c 75 7a 69 63 75 7a 75 20 76 75 76 69 67 6f 77 65 78 61 66 65 78 65 70 6f 6a 6f 6d 69 62 61 20 73 75 68 6f 6d 6f 78 69 6e 65 20 7a 75 78 61 67 65 6e 65 6c 6f 6e 75 67 6f } //1 yeginejiparatudefaf boluzicuzu vuvigowexafexepojomiba suhomoxine zuxagenelonugo
		$a_81_4 = {7a 75 78 69 62 61 6e 61 78 75 6a 61 6d 65 72 61 70 65 6a 69 66 65 64 69 73 75 68 65 79 75 76 20 6c 69 64 75 64 65 70 61 79 75 6b 69 67 20 64 65 6b 69 74 61 66 69 67 61 6a 65 66 65 } //1 zuxibanaxujamerapejifedisuheyuv lidudepayukig dekitafigajefe
		$a_81_5 = {76 75 77 65 6d 69 73 6f } //1 vuwemiso
		$a_81_6 = {62 69 64 65 76 69 6c 75 6d 6f 70 61 6c 6f 7a 69 64 65 70 6f 77 61 79 6f } //1 bidevilumopalozidepowayo
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}