
rule TrojanSpy_Win32_Bancos_ADP{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 } //01 00 
		$a_01_1 = {6f 66 66 20 74 69 74 6c 65 3d 22 55 73 75 61 72 69 6f 3a } //01 00  off title="Usuario:
		$a_01_2 = {49 6d 61 67 65 43 6f 6e 66 69 72 6d 61 72 43 6c 69 63 6b } //00 00  ImageConfirmarClick
	condition:
		any of ($a_*)
 
}