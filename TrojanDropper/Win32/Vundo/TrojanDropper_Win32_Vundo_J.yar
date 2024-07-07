
rule TrojanDropper_Win32_Vundo_J{
	meta:
		description = "TrojanDropper:Win32/Vundo.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 0e 83 c6 04 83 fe 90 01 01 72 e4 33 c0 40 90 00 } //1
		$a_03_1 = {74 17 83 c7 05 83 ff 90 01 01 72 d5 6a 2e 53 ff d5 90 00 } //1
		$a_01_2 = {6a 0f 59 8b f7 83 c2 61 66 89 17 33 d2 f7 f1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}