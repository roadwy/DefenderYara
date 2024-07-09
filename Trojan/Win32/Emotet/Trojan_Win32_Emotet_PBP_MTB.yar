
rule Trojan_Win32_Emotet_PBP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_02_0 = {0f b6 0c 37 0f b6 04 30 03 c1 83 4d ?? ff f7 35 ?? ?? ?? ?? 8b 45 ?? 8d 8d [0-04] 8a 04 18 32 04 32 88 03 } //1
		$a_81_1 = {72 52 58 4b 33 34 46 54 7e 4f 69 3f 38 7d 64 66 65 32 73 33 72 30 77 24 53 50 35 45 58 6e 31 54 53 39 7a 53 57 7a 40 56 75 6d 74 43 65 7b 3f 65 69 72 66 68 4d 6e 7c 44 7a 66 70 7e 51 56 76 47 6c 63 56 7b 55 36 66 5a 68 57 30 57 4e } //1 rRXK34FT~Oi?8}dfe2s3r0w$SP5EXn1TS9zSWz@VumtCe{?eirfhMn|Dzfp~QVvGlcV{U6fZhW0WN
		$a_81_2 = {4f 38 23 39 75 30 56 4a 49 55 65 3f 58 30 34 28 56 59 33 69 39 24 26 74 47 42 75 56 77 75 49 7a 4e 21 48 4d 34 30 54 68 69 69 24 33 30 35 3c 43 66 42 6a 5a 51 72 66 68 4b 61 79 6f 53 72 67 53 63 55 57 4c 24 64 33 70 30 68 50 55 4d 24 23 59 48 73 74 4f 31 6e 7a 4a 4e 30 7a 4c 32 70 44 45 59 63 7a 30 57 38 47 } //1 O8#9u0VJIUe?X04(VY3i9$&tGBuVwuIzN!HM40Thii$305<CfBjZQrfhKayoSrgScUWL$d3p0hPUM$#YHstO1nzJN0zL2pDEYcz0W8G
		$a_81_3 = {44 56 51 23 66 72 79 31 7a 58 7a 6f 6f 75 73 25 2a 3f 6d 73 62 24 3f 3f 39 4f 4a 6f 4f 5a 70 64 4c 59 67 71 25 32 77 73 41 6c 4e 73 44 70 54 39 57 67 6c 53 7c 4a 6c 75 70 45 31 62 72 62 6d 33 72 7a 59 7d 4f 37 4c 78 48 2a 63 54 58 74 71 4d 5a 35 45 } //1 DVQ#fry1zXzoous%*?msb$??9OJoOZpdLYgq%2wsAlNsDpT9WglS|JlupE1brbm3rzY}O7LxH*cTXtqMZ5E
		$a_81_4 = {77 64 48 34 76 52 61 72 57 7a 4b 25 6a 74 36 45 50 45 4b 4d 7e 52 3f 6f 52 48 62 75 58 75 52 43 6b 48 25 48 42 63 6e 7e 43 50 6a 50 7e 75 68 78 61 5a 4d 47 4f 6c 57 7c 65 33 67 58 61 31 62 49 4e 7c 3f 35 23 } //1 wdH4vRarWzK%jt6EPEKM~R?oRHbuXuRCkH%HBcn~CPjP~uhxaZMGOlW|e3gXa1bIN|?5#
		$a_81_5 = {3f 51 57 59 67 59 55 73 35 6f 23 71 6b 3c 6c 21 29 29 6b 62 48 5a 5f 73 21 59 40 66 36 3f 74 4a 73 26 41 69 62 23 78 4a 57 49 } //1 ?QWYgYUs5o#qk<l!))kbHZ_s!Y@f6?tJs&Aib#xJWI
		$a_81_6 = {68 56 70 26 4c 70 68 78 58 4d 28 2a 6e 32 38 25 73 26 23 2a 38 54 5e 2b 31 3c 5a 56 32 57 6a 26 57 30 37 47 25 3f 26 53 6c 73 68 44 78 26 4e 54 53 24 79 26 57 52 78 47 4c 6b 67 55 2a 67 77 51 35 4a 4c 40 6e 54 24 6f 76 6e 37 64 48 47 70 6b } //1 hVp&LphxXM(*n28%s&#*8T^+1<ZV2Wj&W07G%?&SlshDx&NTS$y&WRxGLkgU*gwQ5JL@nT$ovn7dHGpk
		$a_81_7 = {56 29 63 52 6a 6d 43 25 2a 38 69 57 46 4e 40 5a 5f 6b 65 73 66 30 73 61 6d 79 73 2b 41 6b 61 45 64 78 77 4f 21 50 59 30 3f 72 38 32 78 71 6d 33 72 23 24 3e 3e 35 57 43 79 4d 29 39 4c 50 76 79 50 4b 44 43 3c 78 51 4f 36 67 63 55 4e 25 72 28 23 39 51 79 56 46 39 76 4e 26 3f 54 48 } //1 V)cRjmC%*8iWFN@Z_kesf0samys+AkaEdxwO!PY0?r82xqm3r#$>>5WCyM)9LPvyPKDC<xQO6gcUN%r(#9QyVF9vN&?TH
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=1
 
}