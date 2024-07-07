
rule Trojan_Win32_ClipBanker_ASC_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 54 65 61 6d 56 69 65 77 65 72 5f 53 65 72 76 69 63 65 2e 65 78 65 } //1 Users\Public\Downloads\TeamViewer_Service.exe
		$a_01_1 = {74 72 6f 6e 2e 6d 68 78 69 65 79 69 2e 63 6f 6d } //1 tron.mhxieyi.com
		$a_01_2 = {30 78 37 43 39 32 65 64 36 66 39 35 66 33 66 38 32 33 41 61 39 42 33 34 32 35 41 31 39 43 39 63 31 34 33 30 66 37 34 37 39 39 } //1 0x7C92ed6f95f3f823Aa9B3425A19C9c1430f74799
		$a_01_3 = {33 45 74 74 7a 44 42 77 31 32 34 6a 45 56 69 65 51 4b 67 32 76 64 76 57 47 51 53 70 7a 68 64 65 46 6a } //1 3EttzDBw124jEVieQKg2vdvWGQSpzhdeFj
		$a_01_4 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 77 6e 6c 6f 61 64 73 5c 5a 54 58 43 6c 69 65 6e 74 6e 2e 65 78 65 } //1 Users\Public\Downloads\ZTXClientn.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}