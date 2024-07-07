
rule Trojan_AndroidOS_Mamont_R{
	meta:
		description = "Trojan:AndroidOS/Mamont.R,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 68 61 74 5f 69 64 3d 2d 31 30 30 31 39 39 36 32 36 30 34 30 30 26 74 65 78 74 3d d0 92 d0 be d1 80 d0 ba d0 b5 d1 80 3a } //2
		$a_01_1 = {40 73 68 6f 6f 74 69 6e 67 75 70 73 6f 6d 65 } //2 @shootingupsome
		$a_01_2 = {43 6f 64 65 46 72 6f 6d 50 61 6e 65 6c } //2 CodeFromPanel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}