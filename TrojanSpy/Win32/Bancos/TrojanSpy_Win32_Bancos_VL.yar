
rule TrojanSpy_Win32_Bancos_VL{
	meta:
		description = "TrojanSpy:Win32/Bancos.VL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 4d c4 50 51 ff d7 8b 55 d4 50 8d 45 c8 52 50 ff d7 50 56 e8 90 01 02 ff ff 8b f0 90 00 } //1
		$a_01_1 = {8b 4d 0c 8b 11 52 ff d6 89 45 a8 b8 02 00 00 00 be 01 00 00 00 3b 75 a8 0f 8f a3 00 00 00 8b 4d 0c 89 45 c8 89 45 c0 8d 45 c0 8b 11 50 83 c3 01 56 52 0f 80 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}