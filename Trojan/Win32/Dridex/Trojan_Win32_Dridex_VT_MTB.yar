
rule Trojan_Win32_Dridex_VT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.VT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {52 70 6b 64 65 72 33 33 36 } //Rpkder336  3
		$a_80_1 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
		$a_80_2 = {66 70 6e 2e 70 64 62 } //fpn.pdb  3
		$a_80_3 = {37 34 34 73 69 74 65 73 6c 57 33 43 2c } //744siteslW3C,  3
		$a_80_4 = {41 64 62 6c 6f 63 6b 66 65 61 74 75 72 65 73 66 33 36 25 75 34 42 4b 41 } //Adblockfeaturesf36%u4BKA  3
		$a_80_5 = {2c 73 79 73 74 65 6d 2e 31 39 32 45 36 36 36 36 36 36 70 72 6f 63 65 73 73 65 73 5a 73 65 63 75 72 69 74 79 } //,system.192E666666processesZsecurity  3
		$a_80_6 = {77 32 6a 63 6f 6e 6e 65 63 74 65 64 64 77 69 74 68 77 33 2c 6f 6e 63 65 } //w2jconnecteddwithw3,once  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}