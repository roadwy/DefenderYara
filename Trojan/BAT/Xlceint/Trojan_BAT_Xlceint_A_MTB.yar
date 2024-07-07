
rule Trojan_BAT_Xlceint_A_MTB{
	meta:
		description = "Trojan:BAT/Xlceint.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 "
		
	strings :
		$a_80_0 = {78 43 6c 69 65 6e 74 2e 43 6f 72 65 2e 45 6c 65 76 61 74 69 6f 6e } //xClient.Core.Elevation  3
		$a_80_1 = {53 45 4c 45 43 54 20 43 61 70 74 69 6f 6e 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //SELECT Caption FROM Win32_OperatingSystem  3
		$a_80_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntivirusProduct  3
		$a_80_3 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Select * From Win32_ComputerSystem  3
		$a_80_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 46 69 72 65 77 61 6c 6c 50 72 6f 64 75 63 74 } //SELECT * FROM FirewallProduct  3
		$a_80_5 = {64 65 6c 20 2f 41 3a 48 } //del /A:H  3
		$a_80_6 = {35 52 42 33 68 66 50 53 44 52 77 61 53 4d 52 33 62 6d 34 69 } //5RB3hfPSDRwaSMR3bm4i  3
		$a_80_7 = {44 6f 4d 6f 75 73 65 45 76 65 6e 74 } //DoMouseEvent  3
		$a_80_8 = {48 6f 74 4b 65 79 48 61 6e 64 6c 65 72 } //HotKeyHandler  3
		$a_80_9 = {61 64 64 5f 4f 6e 48 6f 74 4b 65 79 73 44 6f 77 6e 4f 6e 63 65 } //add_OnHotKeysDownOnce  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3) >=30
 
}