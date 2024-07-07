
rule TrojanDropper_Win32_Vtimrun_C{
	meta:
		description = "TrojanDropper:Win32/Vtimrun.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 00 50 e8 90 01 02 00 00 8d 85 90 01 02 ff ff c6 90 01 02 44 50 8d 85 90 01 02 ff ff 50 c6 90 01 02 6c c6 90 01 02 6c c6 90 01 02 43 c6 90 01 02 61 c6 90 01 02 63 c6 90 01 02 68 c6 90 01 02 65 c6 90 01 02 5c 88 90 01 02 e8 90 00 } //1
		$a_02_1 = {40 65 63 68 6f 90 02 05 6f 66 66 0d 0a 3a 74 72 79 90 02 07 64 65 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}