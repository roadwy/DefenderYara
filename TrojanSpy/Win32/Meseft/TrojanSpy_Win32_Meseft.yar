
rule TrojanSpy_Win32_Meseft{
	meta:
		description = "TrojanSpy:Win32/Meseft,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 8a 8b 90 01 04 57 30 0c 06 43 e8 90 01 04 3b d8 59 72 90 01 01 8b 44 24 10 50 8a 0c 06 f6 d1 88 0c 06 46 90 00 } //01 00 
		$a_01_1 = {62 72 6f 77 73 65 72 3d 25 73 26 73 69 74 65 3d 25 73 26 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 } //01 00  browser=%s&site=%s&user=%s&pass=%s
		$a_01_2 = {50 4f 53 54 20 2f 67 61 74 65 77 61 79 2f 73 70 72 65 61 64 65 72 73 20 48 54 54 50 2f 31 2e 30 } //01 00  POST /gateway/spreaders HTTP/1.0
		$a_01_3 = {58 2d 4e 69 67 67 65 72 2d 25 63 3a 20 25 75 25 75 } //00 00  X-Nigger-%c: %u%u
	condition:
		any of ($a_*)
 
}