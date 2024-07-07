
rule TrojanDropper_Win32_Rustock_O{
	meta:
		description = "TrojanDropper:Win32/Rustock.O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 81 38 4d 5a 68 90 01 04 60 e8 90 01 02 ff ff 8b 50 10 66 0f ce 60 c7 44 90 01 06 e8 90 01 02 00 00 90 00 } //1
		$a_02_1 = {f5 f5 33 44 24 90 01 01 e9 87 00 00 00 83 f8 00 66 c7 44 24 90 01 03 c6 44 24 90 01 02 60 8d 64 24 90 01 01 0f 85 90 01 02 00 00 9c 9c 90 90 90 02 04 9c e8 00 00 00 00 c7 44 24 90 01 03 40 00 83 ec f4 68 90 01 04 e8 90 01 02 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}