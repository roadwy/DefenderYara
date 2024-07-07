
rule Trojan_Win64_Filisto_E_dha{
	meta:
		description = "Trojan:Win64/Filisto.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 6f 6e 6f 74 62 6f 74 68 65 72 6d 65 } //2 donotbotherme
		$a_01_1 = {46 58 53 41 50 49 44 65 62 75 67 4c 6f 67 46 69 6c 65 2e 74 6d 70 } //2 FXSAPIDebugLogFile.tmp
		$a_01_2 = {54 72 79 20 48 74 74 70 73 20 62 79 20 57 50 41 44 50 72 6f 78 79 2e } //2 Try Https by WPADProxy.
		$a_01_3 = {47 65 74 20 46 69 72 65 46 6f 78 50 72 6f 78 79 20 25 73 } //1 Get FireFoxProxy %s
		$a_01_4 = {4f 70 65 6e 48 74 74 70 42 79 4e 6f 50 72 6f 78 79 20 57 69 6e 48 74 74 70 4f 70 65 6e 20 46 61 69 6c 65 64 21 20 2d 20 25 64 } //1 OpenHttpByNoProxy WinHttpOpen Failed! - %d
		$a_01_5 = {6d 5f 63 6c 69 65 6e 74 5f 68 65 61 64 20 42 61 73 65 36 34 45 6e 63 6f 64 65 20 66 61 69 6c 21 } //1 m_client_head Base64Encode fail!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}