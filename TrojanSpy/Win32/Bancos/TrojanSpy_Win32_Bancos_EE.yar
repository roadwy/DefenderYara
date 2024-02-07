
rule TrojanSpy_Win32_Bancos_EE{
	meta:
		description = "TrojanSpy:Win32/Bancos.EE,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 45 43 32 40 4f 00 } //05 00 
		$a_01_1 = {8b 45 f8 8b 55 e8 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f4 7d 03 46 eb 05 be 01 00 00 00 8b 45 ec 0f b6 44 30 ff 33 d8 } //0a 00 
		$a_01_2 = {61 70 6c 69 63 61 74 69 76 6f 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 64 64 72 65 73 73 } //00 00  aplicativos\Microsoft\Address
	condition:
		any of ($a_*)
 
}