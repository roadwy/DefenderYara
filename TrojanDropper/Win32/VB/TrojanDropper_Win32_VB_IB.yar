
rule TrojanDropper_Win32_VB_IB{
	meta:
		description = "TrojanDropper:Win32/VB.IB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 00 68 00 6e 00 67 00 68 00 6a 00 74 00 75 00 79 00 79 00 74 00 67 00 62 00 68 00 74 00 67 00 72 00 } //4 nhnghjtuyytgbhtgr
		$a_01_1 = {44 45 43 52 59 50 54 46 69 4c 45 } //4 DECRYPTFiLE
		$a_01_2 = {74 00 6f 00 6d 00 61 00 65 00 73 00 74 00 6f 00 65 00 73 00 70 00 61 00 72 00 61 00 76 00 6f 00 73 00 6d 00 61 00 72 00 69 00 63 00 6f 00 6e 00 } //3 tomaestoesparavosmaricon
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=11
 
}