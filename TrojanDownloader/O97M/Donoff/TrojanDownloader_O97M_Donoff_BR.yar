
rule TrojanDownloader_O97M_Donoff_BR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 4e 62 42 69 61 30 20 3d 20 6d 73 54 54 47 5a 75 41 78 4a 74 20 2d 20 28 28 6d 73 54 54 47 5a 75 41 78 4a 74 20 5c 20 66 4f 6f 56 39 74 44 51 29 20 2a 20 66 4f 6f 56 39 74 44 51 29 } //1 bNbBia0 = msTTGZuAxJt - ((msTTGZuAxJt \ fOoV9tDQ) * fOoV9tDQ)
		$a_00_1 = {46 4c 44 31 56 51 20 3d 20 28 61 34 75 61 62 47 70 20 2d 20 45 31 34 55 61 53 6c 78 30 79 29 20 2f 20 74 49 70 75 46 34 47 43 66 4b 72 79 56 55 73 28 46 72 63 6e 47 71 78 32 29 } //1 FLD1VQ = (a4uabGp - E14UaSlx0y) / tIpuF4GCfKryVUs(FrcnGqx2)
		$a_00_2 = {65 78 54 6a 43 50 54 58 77 45 39 66 74 28 4d 50 71 71 48 36 2c 20 28 48 62 33 6a 45 45 57 78 79 20 2a 20 45 31 34 55 61 53 6c 78 30 79 29 20 2b 20 69 30 53 4c 41 42 53 29 } //1 exTjCPTXwE9ft(MPqqH6, (Hb3jEEWxy * E14UaSlx0y) + i0SLABS)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_BR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {37 37 75 2f 58 45 46 77 63 45 52 68 64 47 46 63 55 6d 39 68 62 57 6c 75 5a 31 78 4e 61 57 4e 79 62 33 4e 76 5a 6e 52 63 56 32 6c 75 5a 47 39 33 63 31 78 55 5a 57 31 77 62 47 46 30 5a 58 4e 63 54 6d 56 33 49 45 31 70 59 33 4a 76 63 32 39 6d 64 43 42 46 65 47 4e 6c 62 43 42 58 62 33 4a 72 63 32 68 6c 5a 58 51 75 65 47 78 7a } //1 77u/XEFwcERhdGFcUm9hbWluZ1xNaWNyb3NvZnRcV2luZG93c1xUZW1wbGF0ZXNcTmV3IE1pY3Jvc29mdCBFeGNlbCBXb3Jrc2hlZXQueGxz
		$a_01_1 = {37 37 75 2f 58 45 46 77 63 45 52 68 64 47 46 63 55 6d 39 68 62 57 6c 75 5a 31 78 4e 61 57 4e 79 62 33 4e 76 5a 6e 52 63 56 32 6c 75 5a 47 39 33 63 31 78 55 5a 57 31 77 62 47 46 30 5a 58 4e 63 62 6d 56 33 4c 6e 52 74 63 41 3d 3d } //1 77u/XEFwcERhdGFcUm9hbWluZ1xNaWNyb3NvZnRcV2luZG93c1xUZW1wbGF0ZXNcbmV3LnRtcA==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}