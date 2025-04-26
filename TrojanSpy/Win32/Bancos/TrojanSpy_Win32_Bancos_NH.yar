
rule TrojanSpy_Win32_Bancos_NH{
	meta:
		description = "TrojanSpy:Win32/Bancos.NH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 48 74 2b 66 55 70 43 52 55 74 4d 55 46 42 63 58 6c 6c 69 5a 57 4a 75 62 6d 79 70 73 4b 65 77 73 63 4b 42 76 73 57 38 78 63 62 58 6c 64 54 64 31 77 3d 3d } //5 bHt+fUpCRUtMUFBcXlliZWJubmypsKewscKBvsW8xcbXldTd1w==
		$a_01_1 = {b8 1c 01 45 00 e8 c1 e8 ff ff 8b 55 bc 58 e8 d0 46 fb ff 8b 45 c0 e8 14 87 fb ff } //1
		$a_01_2 = {b8 c8 b9 49 00 e8 0b 03 fc ff 8b 85 14 fe ff ff 50 8d 85 10 fe ff ff e8 0d e9 ff ff 8b 95 10 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}