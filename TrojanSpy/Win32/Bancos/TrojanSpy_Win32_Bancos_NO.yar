
rule TrojanSpy_Win32_Bancos_NO{
	meta:
		description = "TrojanSpy:Win32/Bancos.NO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 54 17 ff 8b ce c1 e9 08 32 d1 e8 90 01 04 8b 55 f4 8b 45 08 e8 90 01 04 8b 45 08 33 c0 8a c3 0f b6 44 07 ff 03 f0 0f af 75 fc 03 75 0c 43 fe 4d fb 75 c3 90 00 } //01 00 
		$a_01_1 = {61 72 71 75 69 76 6f 73 2f 73 75 63 63 65 73 73 66 75 6c 2e 70 68 70 00 } //01 00 
		$a_01_2 = {63 6f 72 72 6f 6d 70 69 64 6f 21 00 } //00 00  潣牲浯楰潤!
	condition:
		any of ($a_*)
 
}