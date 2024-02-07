
rule TrojanSpy_Win32_Bancos_RB{
	meta:
		description = "TrojanSpy:Win32/Bancos.RB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 72 61 64 65 73 63 6f 20 6e 65 74 20 65 6d 70 72 65 73 61 } //01 00  bradesco net empresa
		$a_00_1 = {3a 2f 2f 25 73 3a 25 64 2f 25 73 3f 55 49 44 3d 25 73 3b 50 57 44 3d 25 73 } //01 00  ://%s:%d/%s?UID=%s;PWD=%s
		$a_01_2 = {be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 c3 89 45 e0 3b 7d e0 7c 0f 8b 45 e0 05 ff 00 00 00 2b c7 } //00 00 
	condition:
		any of ($a_*)
 
}