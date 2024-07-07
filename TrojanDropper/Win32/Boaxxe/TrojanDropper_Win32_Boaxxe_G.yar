
rule TrojanDropper_Win32_Boaxxe_G{
	meta:
		description = "TrojanDropper:Win32/Boaxxe.G,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {35 aa 55 c3 01 50 90 02 08 e8 90 01 02 ff ff 90 02 08 02 c3 fa 13 90 00 } //10
		$a_02_1 = {35 02 c3 fa 13 90 02 06 81 f2 aa 55 c3 01 90 02 08 e8 90 00 } //10
		$a_00_2 = {8b 40 3c 83 c0 14 05 e0 00 00 00 83 c0 04 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1) >=11
 
}