
rule TrojanDropper_Win32_Jeshex_A{
	meta:
		description = "TrojanDropper:Win32/Jeshex.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 d0 80 fa 00 74 } //1
		$a_01_1 = {ff 75 14 6a 02 6a 00 6a 00 68 00 00 00 c0 } //1
		$a_01_2 = {ff 75 18 6a 00 ff 75 28 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}