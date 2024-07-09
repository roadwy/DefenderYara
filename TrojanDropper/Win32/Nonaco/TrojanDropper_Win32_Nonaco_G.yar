
rule TrojanDropper_Win32_Nonaco_G{
	meta:
		description = "TrojanDropper:Win32/Nonaco.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 00 00 67 73 76 72 33 32 20 2f 73 } //2
		$a_03_1 = {75 47 8d 85 ?? ?? ff ff 68 e9 03 00 00 } //1
		$a_01_2 = {8d 84 24 d8 00 00 00 68 e9 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}