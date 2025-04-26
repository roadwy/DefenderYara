
rule TrojanDropper_Win32_Swapexo_A{
	meta:
		description = "TrojanDropper:Win32/Swapexo.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3b ef 73 1a 8a 08 84 c9 75 05 c6 00 58 eb 08 80 f9 58 75 03 c6 00 00 83 c0 01 3b c7 72 e6 } //2
		$a_01_1 = {64 3a 5c 76 73 50 72 6f 6a 65 63 74 73 5c 69 6f 73 65 74 75 70 5c 52 65 6c 65 61 73 65 5c 69 6f 73 65 74 75 70 2e 70 64 62 } //2 d:\vsProjects\iosetup\Release\iosetup.pdb
		$a_01_2 = {47 6c 6f 62 61 6c 5c 74 74 74 6d 6d 6d 74 74 74 00 } //1
		$a_01_3 = {74 74 74 6b 6b 6b 74 74 74 00 } //1 瑴歴歫瑴t
		$a_01_4 = {69 6f 66 69 6c 74 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}