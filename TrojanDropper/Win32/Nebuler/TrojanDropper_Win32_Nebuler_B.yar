
rule TrojanDropper_Win32_Nebuler_B{
	meta:
		description = "TrojanDropper:Win32/Nebuler.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_0b_0 = {81 ff b7 00 00 00 74 90 01 01 83 ff 05 90 00 } //1
		$a_09_1 = {53 68 11 01 00 00 68 ff ff 00 00 } //1
		$a_09_2 = {81 7e 08 11 01 00 00 } //1
		$a_01_3 = {ff ff 2a cb 80 14 75 0f } //2
	condition:
		((#a_0b_0  & 1)*1+(#a_09_1  & 1)*1+(#a_09_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}