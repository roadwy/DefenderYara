
rule TrojanDropper_Win32_Rovnix_H{
	meta:
		description = "TrojanDropper:Win32/Rovnix.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 3c 30 33 75 09 81 3c 30 33 33 33 33 74 09 83 c0 01 3b c7 72 ea } //1
		$a_01_1 = {8b 2c 86 03 ea 33 6b 0a 8a ca d3 c5 83 c0 01 83 ea 01 3b 44 24 48 89 6c 86 fc 72 e4 } //1
		$a_01_2 = {81 3c 31 77 77 77 77 74 16 41 3b cf 72 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}