
rule TrojanSpy_Win32_Bancos_ACM{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 } //01 00 
		$a_00_1 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //01 00 
		$a_03_2 = {8b 45 0c 33 db 8b d0 83 ea 02 74 0a 81 ea ff 03 00 00 74 0b eb 90 01 01 6a 00 e8 90 01 04 eb 90 01 01 a1 90 01 04 e8 90 01 04 a1 90 01 04 e8 90 01 04 68 e8 03 00 00 e8 90 01 04 e8 90 01 04 68 e8 03 00 00 e8 90 01 04 e8 90 01 04 6a 00 6a 00 6a 02 8b 45 08 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}