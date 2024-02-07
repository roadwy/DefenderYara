
rule TrojanProxy_Win32_Banker_BB{
	meta:
		description = "TrojanProxy:Win32/Banker.BB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 4b 65 6c 6c 5f 4d 61 72 71 75 65 73 } //01 00  TKell_Marques
		$a_03_1 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 01 0a 43 3a 5c 46 6f 74 6f 36 32 35 33 34 2e 65 78 65 00 90 00 } //01 00 
		$a_03_2 = {74 69 70 3d 90 01 0c 74 69 70 6f 3d 69 6e 66 90 00 } //01 00 
		$a_03_3 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c 90 01 2e 5c 70 72 65 66 73 2e 6a 73 90 00 } //01 00 
		$a_01_4 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 22 68 74 74 70 3a 2f 2f 77 77 77 2e } //01 00  user_pref("network.proxy.autoconfig_url","http://www.
		$a_01_5 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 22 2c 20 32 29 3b } //01 00  user_pref("network.proxy.type", 2);
		$a_03_6 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 90 01 0b 30 78 30 30 30 30 30 30 30 30 00 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 8c } //08 03 
	condition:
		any of ($a_*)
 
}