
rule Worm_Win32_Mofksys_gen_A{
	meta:
		description = "Worm:Win32/Mofksys.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 93 24 49 92 2b ca 0f 80 3f 02 00 00 f7 e9 03 d1 c1 fa 03 8b ca c1 e9 1f } //2
		$a_01_1 = {8d 55 d4 52 66 8b 55 be 66 6b d2 28 0f 80 48 02 00 00 0f bf d2 52 8b 49 0c } //2
		$a_01_2 = {3c 00 2f 00 78 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3e 00 } //1 </xCommand>
		$a_01_3 = {3c 00 2f 00 44 00 62 00 6c 00 43 00 6c 00 6b 00 3e 00 } //1 </DblClk>
		$a_01_4 = {3c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3e 00 } //1 <Download>
		$a_01_5 = {26 00 48 00 41 00 38 00 } //1 &HA8
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}