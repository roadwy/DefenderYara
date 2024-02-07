
rule TrojanSpy_Win32_Potian_A{
	meta:
		description = "TrojanSpy:Win32/Potian.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6f 6f 6b 2e 64 6c 6c } //01 00  hook.dll
		$a_01_1 = {73 74 61 72 68 6f 6f 6b } //01 00  starhook
		$a_01_2 = {32 31 39 2e 31 35 33 2e 35 31 2e 34 37 } //01 00  219.153.51.47
		$a_01_3 = {00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 63 68 69 6e 61 5f 6c 6f 67 69 6e 2e 6d 70 72 } //00 00 
	condition:
		any of ($a_*)
 
}