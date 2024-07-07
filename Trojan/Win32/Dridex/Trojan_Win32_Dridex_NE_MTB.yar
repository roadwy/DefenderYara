
rule Trojan_Win32_Dridex_NE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 4d f7 88 ca 80 e2 e4 88 55 f7 8b 75 08 88 4d f7 83 fe 00 89 45 e8 } //10
		$a_81_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //3 FFPGGLBM.pdb
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}
rule Trojan_Win32_Dridex_NE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.NE!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 00 53 00 54 00 41 00 50 00 50 00 20 00 45 00 5f 00 } //1 ESTAPP E_
		$a_01_1 = {65 00 6c 00 66 00 20 00 45 00 58 00 } //1 elf EX
		$a_01_2 = {31 00 5a 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 2c 00 6d 00 65 00 63 00 68 00 61 00 6e 00 69 00 73 00 6d 00 73 00 31 00 53 00 62 00 63 00 39 00 57 00 } //1 1ZModule,mechanisms1Sbc9W
		$a_01_3 = {64 70 70 7c 70 70 2e 70 64 62 } //1 dpp|pp.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}