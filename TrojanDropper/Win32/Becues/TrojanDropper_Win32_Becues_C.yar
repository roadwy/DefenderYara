
rule TrojanDropper_Win32_Becues_C{
	meta:
		description = "TrojanDropper:Win32/Becues.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 85 c0 76 0d 8a 54 0c 90 01 01 30 54 0c 14 41 3b c8 72 f3 6a 01 6a 00 f7 d8 50 90 01 01 ff 90 00 } //1
		$a_03_1 = {83 c1 01 3b c8 72 f1 6a 01 6a 00 f7 d8 50 90 01 01 ff 90 09 08 00 8a 54 0c 90 01 01 30 54 0c 90 17 03 01 01 01 14 24 2c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}