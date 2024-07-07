
rule TrojanDropper_Win32_Zolpiq_A{
	meta:
		description = "TrojanDropper:Win32/Zolpiq.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 3a 8b 4f 04 8b 56 0c 3b ca 72 30 8b 46 10 03 c2 3b c8 73 27 8b 46 14 2b c2 } //1
		$a_01_1 = {59 8b c1 83 c0 24 50 81 c1 00 00 00 00 3e 8b 01 05 00 00 00 00 ff d0 } //1
		$a_01_2 = {6d 73 74 64 33 32 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}