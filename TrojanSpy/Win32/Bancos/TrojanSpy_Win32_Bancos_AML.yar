
rule TrojanSpy_Win32_Bancos_AML{
	meta:
		description = "TrojanSpy:Win32/Bancos.AML,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d3 b8 01 00 00 00 66 03 c7 0f 80 9d 00 00 00 8b f8 e9 e3 fe ff ff 8d 4d d0 ff d7 } //1
		$a_03_1 = {83 c4 0c 81 e6 ff 00 00 00 52 56 ff 15 90 01 04 8b 35 90 01 04 8b d0 8d 4d c4 ff d6 50 ff 15 90 00 } //1
		$a_03_2 = {2e 00 74 00 6d 00 70 90 09 14 00 5f 5f 76 62 61 53 74 72 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}