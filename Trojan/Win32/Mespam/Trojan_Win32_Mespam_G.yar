
rule Trojan_Win32_Mespam_G{
	meta:
		description = "Trojan:Win32/Mespam.G,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0f 00 08 00 00 "
		
	strings :
		$a_00_0 = {57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 } //1 WSCWriteProviderOrder
		$a_00_1 = {57 53 43 49 6e 73 74 61 6c 6c 50 72 6f 76 69 64 65 72 } //1 WSCInstallProvider
		$a_00_2 = {6e 65 77 73 69 67 68 2e 63 6f 6d } //1 newsigh.com
		$a_00_3 = {2f 6e 65 77 73 6a 2e 70 68 70 } //1 /newsj.php
		$a_00_4 = {5a 61 65 62 69 7a 2e 47 6f 6f 67 6c 65 53 65 61 72 63 68 2e 4c 73 70 2e 4d 75 74 65 78 } //1 Zaebiz.GoogleSearch.Lsp.Mutex
		$a_00_5 = {7b 22 6d 61 63 68 69 6e 65 5f 69 64 22 3a 22 61 62 63 64 65 66 67 68 69 6a 6b 6c 22 2c 22 68 69 73 74 6f 72 79 22 3a 22 22 7d } //1 {"machine_id":"abcdefghijkl","history":""}
		$a_00_6 = {5e 28 47 45 54 7c 50 4f 53 54 29 5c 73 2b 28 2e 2b 29 5c 73 2b 48 54 54 50 5c 2f 5c 64 5c 2e 5c 64 } //1 ^(GET|POST)\s+(.+)\s+HTTP\/\d\.\d
		$a_02_7 = {74 24 81 fe a0 00 00 00 75 07 e8 ?? ?? 00 00 eb 15 81 fe 02 02 00 00 74 08 81 fe a2 00 00 00 75 05 e8 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*10) >=15
 
}