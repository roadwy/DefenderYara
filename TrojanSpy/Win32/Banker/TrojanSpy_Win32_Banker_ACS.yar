
rule TrojanSpy_Win32_Banker_ACS{
	meta:
		description = "TrojanSpy:Win32/Banker.ACS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 73 6e 58 54 63 4b 57 52 63 79 57 54 6b 35 69 51 4d 48 58 42 57 } //1 GsnXTcKWRcyWTk5iQMHXBW
		$a_01_1 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c 72 66 6b 73 61 64 76 6e 71 69 6e 64 79 77 33 6e 65 72 61 73 64 66 } //1 =_NextPart_2relrfksadvnqindyw3nerasdf
		$a_01_2 = {41 4c 4c 3a 21 41 44 48 3a 52 43 34 2b 52 53 41 3a 2b 48 49 47 48 3a 2b 4d 45 44 49 55 4d 3a 2b 4c 4f 57 3a 2b 53 53 4c 76 32 3a 2b 45 58 50 00 } //1 䱁㩌䄡䡄刺㑃别䅓⬺䥈䡇⬺䕍䥄䵕⬺佌㩗匫䱓㉶⬺塅P
		$a_01_3 = {7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}