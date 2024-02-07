
rule TrojanSpy_Win32_Derusbi_B_dha{
	meta:
		description = "TrojanSpy:Win32/Derusbi.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 44 46 54 4d 50 24 24 24 24 24 24 2e 31 00 } //01 00 
		$a_01_1 = {50 43 43 5f 49 44 45 4e 54 } //01 00  PCC_IDENT
		$a_01_2 = {50 43 43 5f 43 4d 44 } //01 00  PCC_CMD
		$a_01_3 = {5f 24 24 24 24 24 24 00 2e 63 6d 64 00 } //01 00 
		$a_01_4 = {50 4f 53 54 20 2f 70 68 6f 74 6f 73 2f 70 68 6f 74 6f 2e 61 73 70 20 48 54 54 50 2f 31 2e 31 } //01 00  POST /photos/photo.asp HTTP/1.1
		$a_01_5 = {25 77 69 6e 64 69 72 25 5c 74 65 6d 70 5c 63 6f 6e 69 6d 65 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}