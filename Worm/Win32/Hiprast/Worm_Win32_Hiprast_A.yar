
rule Worm_Win32_Hiprast_A{
	meta:
		description = "Worm:Win32/Hiprast.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 61 72 73 69 42 61 73 68 } //1 ParsiBash
		$a_01_1 = {48 00 4d 00 44 00 43 00 6f 00 72 00 50 00 2e 00 76 00 62 00 70 00 } //1 HMDCorP.vbp
		$a_01_2 = {54 69 6d 65 72 5f 43 6f 70 79 41 68 61 6e 67 } //1 Timer_CopyAhang
		$a_01_3 = {48 4d 44 20 47 72 6f 75 70 } //1 HMD Group
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}