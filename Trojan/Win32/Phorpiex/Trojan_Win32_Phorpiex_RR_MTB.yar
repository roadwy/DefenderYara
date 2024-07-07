
rule Trojan_Win32_Phorpiex_RR_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 7a 75 68 65 6a 61 74 69 6b 69 68 75 7a 69 7a 6f 74 69 39 34 20 76 75 74 65 6b 2d 77 6f 74 61 6d 75 5c 6a 61 62 65 72 75 63 65 72 65 2d 6c 75 6a 61 77 6f 2e 70 64 62 } //1 C:\zuhejatikihuzizoti94 vutek-wotamu\jaberucere-lujawo.pdb
		$a_01_1 = {68 6f 6e 65 79 2e 70 64 62 } //1 honey.pdb
		$a_01_2 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 41 } //1 GetMonitorInfoA
		$a_01_3 = {57 69 6e 48 74 74 70 47 65 74 44 65 66 61 75 6c 74 50 72 6f 78 79 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 WinHttpGetDefaultProxyConfiguration
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}