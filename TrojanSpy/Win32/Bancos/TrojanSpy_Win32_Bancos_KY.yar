
rule TrojanSpy_Win32_Bancos_KY{
	meta:
		description = "TrojanSpy:Win32/Bancos.KY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 64 00 67 00 74 00 34 00 68 00 } //01 00  hdgt4h
		$a_01_1 = {e8 00 6b 00 73 00 5f 00 c1 00 35 00 bd 00 ca 00 2f 00 c2 00 e6 00 e8 00 2b 00 30 00 5c 00 6b 00 2a 00 6f 00 b2 00 e8 00 3b 00 4a 00 2c 00 28 00 65 00 00 00 } //01 00 
		$a_03_2 = {8a 04 11 8b 4d d4 03 c8 0f 80 90 01 02 00 00 8b 55 cc 8b 42 0c 8b 95 f8 fe ff ff 33 db 8a 1c 10 03 cb 0f 80 90 01 02 00 00 0f bf 75 c0 8b c1 99 f7 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}