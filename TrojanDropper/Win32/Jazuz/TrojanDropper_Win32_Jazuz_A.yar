
rule TrojanDropper_Win32_Jazuz_A{
	meta:
		description = "TrojanDropper:Win32/Jazuz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 74 65 6d 70 2e 74 6d 70 00 } //1
		$a_81_1 = {5c 72 75 6e 2e 6a 61 72 00 } //1
		$a_81_2 = {2d 6a 61 72 20 22 25 73 22 20 22 25 73 22 00 } //1
		$a_03_3 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 90 02 0a ff 15 90 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}