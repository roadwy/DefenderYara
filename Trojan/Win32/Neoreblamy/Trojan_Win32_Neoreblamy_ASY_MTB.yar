
rule Trojan_Win32_Neoreblamy_ASY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 4a 43 62 77 4b 75 70 6b 75 58 75 4a 61 50 6a 71 41 52 49 6f 7a 75 65 43 4b 4c 6b 4b 54 } //1 TJCbwKupkuXuJaPjqARIozueCKLkKT
		$a_01_1 = {69 73 62 74 52 42 48 74 64 49 78 4c 45 66 42 70 46 70 6e 4e 66 61 6e 41 4a 4b 64 49 63 52 79 49 77 41 } //1 isbtRBHtdIxLEfBpFpnNfanAJKdIcRyIwA
		$a_01_2 = {47 76 45 45 68 79 79 65 77 52 74 63 77 6b 65 52 67 5a 66 55 63 70 66 55 41 } //1 GvEEhyyewRtcwkeRgZfUcpfUA
		$a_01_3 = {78 70 42 77 74 41 49 59 67 69 4a 6a 42 72 51 70 70 63 44 6b 64 41 64 68 71 54 64 6e 78 6e } //1 xpBwtAIYgiJjBrQppcDkdAdhqTdnxn
		$a_01_4 = {6e 6e 48 51 55 71 65 44 4a 4e 61 46 79 52 5a 66 76 50 75 71 67 43 6f 59 79 44 76 55 } //1 nnHQUqeDJNaFyRZfvPuqgCoYyDvU
		$a_01_5 = {4d 57 78 50 72 63 45 4f 57 55 77 41 75 55 4d 4c 76 7a 79 4a 79 46 77 42 59 42 7a 6e 79 6d 4b 4c 68 6b } //1 MWxPrcEOWUwAuUMLvzyJyFwBYBznymKLhk
		$a_01_6 = {56 58 4a 51 6a 66 6c 63 6d 77 71 56 53 45 65 6e 64 47 53 73 71 73 64 74 7a 6b 55 7a 4c 43 48 65 41 6c 4f 45 45 } //1 VXJQjflcmwqVSEendGSsqsdtzkUzLCHeAlOEE
		$a_01_7 = {76 6a 46 4d 42 49 55 51 4b 46 59 70 79 64 79 73 4a 71 77 55 72 64 73 50 45 5a 58 47 73 66 4f 6a 4b 50 42 4c 59 66 64 6e 79 6a 5a 55 49 75 45 79 68 41 78 } //1 vjFMBIUQKFYpydysJqwUrdsPEZXGsfOjKPBLYfdnyjZUIuEyhAx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}