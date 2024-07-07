
rule Trojan_Win32_Dridex_QS_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_02_0 = {8d 84 0a 18 64 00 00 2b 45 e4 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 81 e9 18 64 00 00 89 0d 90 01 04 8b 15 90 01 04 03 55 e4 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 e4 8b 0d 90 01 04 2b c8 89 0d 90 01 04 ba c5 01 00 00 90 00 } //10
		$a_80_1 = {47 65 29 4d 6f 64 20 6c 65 48 } //Ge)Mod leH  3
		$a_80_2 = {4c 62 72 61 47 79 45 78 34 } //LbraGyEx4  3
		$a_80_3 = {26 54 68 75 73 20 70 3e 67 67 72 3d 69 20 63 3d 6a 6e 6f 40 20 62 65 6c 72 75 6e 7c 6d 6e } //&Thus p>ggr=i c=jno@ belrun|mn  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}