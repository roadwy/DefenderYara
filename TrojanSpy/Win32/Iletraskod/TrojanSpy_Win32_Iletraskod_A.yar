
rule TrojanSpy_Win32_Iletraskod_A{
	meta:
		description = "TrojanSpy:Win32/Iletraskod.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {6c 00 63 00 72 00 65 00 76 00 65 00 6e 00 74 00 6f 00 73 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 } //02 00  lcreventos.ddns.net
		$a_01_1 = {49 45 54 61 73 6b 2e 64 6c 6c 00 41 63 74 69 76 65 } //02 00 
		$a_01_2 = {43 6f 6e 6e 65 63 74 42 61 6e 6b 00 44 69 73 63 6f 6e 6e 65 63 74 } //02 00  潃湮捥䉴湡k楄捳湯敮瑣
		$a_01_3 = {23 56 45 52 53 49 4f 4e 2d 4c 43 2d 32 2e 30 2e 30 2e 37 } //01 00  #VERSION-LC-2.0.0.7
		$a_03_4 = {85 c0 74 2e f6 43 1c 01 75 1d 80 7b 40 00 74 17 8b 0d 90 01 03 00 b2 01 90 00 } //01 00 
		$a_01_5 = {3a 50 40 74 1a f6 40 1c 10 75 06 f6 40 1c 01 74 03 88 50 40 f6 40 1c 01 75 05 8b 08 ff 51 48 } //01 00 
		$a_01_6 = {eb f0 ff 45 f0 83 7d f0 37 0f 85 43 ff ff ff 33 c0 5a 59 59 } //00 00 
		$a_00_7 = {87 10 00 00 b1 } //9e 97 
	condition:
		any of ($a_*)
 
}