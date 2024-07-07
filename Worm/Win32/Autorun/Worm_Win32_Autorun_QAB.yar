
rule Worm_Win32_Autorun_QAB{
	meta:
		description = "Worm:Win32/Autorun.QAB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 73 62 63 61 73 68 2e 65 78 65 90 02 30 41 75 74 6f 52 75 6e 2e 69 6e 66 90 02 30 5b 41 75 74 6f 52 75 6e 5d 90 00 } //10
		$a_03_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 90 02 30 73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74 90 00 } //10
		$a_01_2 = {54 57 6f 72 6d 55 53 42 } //10 TWormUSB
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}