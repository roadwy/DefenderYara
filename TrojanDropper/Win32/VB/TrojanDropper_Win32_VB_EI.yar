
rule TrojanDropper_Win32_VB_EI{
	meta:
		description = "TrojanDropper:Win32/VB.EI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 10 00 00 00 46 69 6e 64 45 78 65 63 75 74 61 62 6c 65 41 00 90 01 34 0a 00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 90 00 } //1
		$a_03_1 = {f5 26 00 00 00 04 90 01 02 0a 01 00 08 00 04 90 01 02 f5 48 00 00 00 04 90 01 02 0a 01 00 08 00 04 90 01 02 fb ef 34 ff 28 90 01 02 02 00 f5 01 00 00 00 6c 90 01 02 f5 01 00 00 00 ae f5 02 00 00 00 b2 aa 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}