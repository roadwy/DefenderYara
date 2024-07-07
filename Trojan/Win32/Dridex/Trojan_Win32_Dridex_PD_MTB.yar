
rule Trojan_Win32_Dridex_PD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {66 6f 72 51 59 69 6e 4c } //1 forQYinL
		$a_81_1 = {66 69 72 73 74 62 79 63 79 63 6c 65 6a } //1 firstbycyclej
		$a_81_2 = {46 6c 61 73 68 2c 76 61 6e 64 43 68 72 6f 6d 65 63 6f 75 6c 64 49 34 46 65 61 63 68 } //1 Flash,vandChromecouldI4Feach
		$a_81_3 = {45 43 68 72 6f 6d 65 42 74 68 65 42 } //1 EChromeBtheB
		$a_81_4 = {74 68 65 43 62 74 68 61 74 42 } //1 theCbthatB
		$a_81_5 = {77 68 69 63 68 34 5a 69 6e } //1 which4Zin
		$a_81_6 = {58 4a 4c 54 75 73 65 72 73 64 31 32 31 32 } //1 XJLTusersd1212
		$a_81_7 = {49 43 49 6d 61 67 65 44 65 63 6f 6d 70 72 65 73 73 } //1 ICImageDecompress
		$a_81_8 = {46 47 54 4e 7c 46 47 54 23 52 36 35 2e 70 64 62 } //1 FGTN|FGT#R65.pdb
		$a_81_9 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Oracle Corporation
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}