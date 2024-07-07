
rule TrojanDropper_Win32_Oficla_B{
	meta:
		description = "TrojanDropper:Win32/Oficla.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 5c 24 08 c7 44 24 04 90 01 04 c7 04 24 90 01 04 e8 90 09 03 00 83 ec 0c 90 00 } //1
		$a_01_1 = {eb 0b 83 c3 01 39 5f 18 76 } //1
		$a_01_2 = {31 c3 89 d8 5b 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}