
rule Worm_Win32_Neeris_AS{
	meta:
		description = "Worm:Win32/Neeris.AS,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 6f 5f 76 6f 6f 5f 64 6f 6f 5f 4f 6e 5f 59 6f 75 72 5f 4d 6f 6d 73 5f 50 75 73 73 79 } //1 Do_voo_doo_On_Your_Moms_Pussy
		$a_01_1 = {6d 65 74 61 6c 2d 72 75 6c 65 73 2d 70 6f 70 2d 73 75 78 } //1 metal-rules-pop-sux
		$a_01_2 = {4c 41 4e 4d 41 4e 31 2e 30 } //10 LANMAN1.0
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 25 73 } //10 Content-Type: %s
		$a_01_4 = {73 61 6e 64 62 6f 78 00 76 6d 77 61 72 65 } //10 慳摮潢x浶慷敲
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=31
 
}