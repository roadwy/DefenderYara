
rule TrojanSpy_Win32_Banker_AAV{
	meta:
		description = "TrojanSpy:Win32/Banker.AAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 64 61 74 65 2f 72 62 2e 70 68 70 3f 68 65 6c 6c 6f 00 } //01 00 
		$a_00_1 = {5c 69 6e 66 2e 74 78 74 00 } //01 00 
		$a_00_2 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 } //01 00  user_pref("network.proxy.autoconfig_url"
		$a_01_3 = {45 72 61 73 65 20 22 25 73 22 } //01 00  Erase "%s"
		$a_01_4 = {4d 65 75 20 50 48 41 52 4d 5c 45 58 45 5c 50 65 72 66 65 63 54 } //00 00  Meu PHARM\EXE\PerfecT
	condition:
		any of ($a_*)
 
}