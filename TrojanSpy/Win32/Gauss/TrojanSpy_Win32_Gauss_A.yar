
rule TrojanSpy_Win32_Gauss_A{
	meta:
		description = "TrojanSpy:Win32/Gauss.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 2c 01 00 00 8d 85 90 01 01 ff ff ff 50 56 e8 90 01 02 00 00 ff 75 64 81 c6 2c 01 00 00 53 56 e8 90 01 02 00 00 83 c4 18 57 57 ff 75 6c 56 57 57 ff 15 90 00 } //01 00 
		$a_02_1 = {57 6a 0d e8 90 01 03 00 59 59 89 45 f0 c6 45 fc 05 85 c0 74 90 01 01 8b 4b 0c 83 60 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}