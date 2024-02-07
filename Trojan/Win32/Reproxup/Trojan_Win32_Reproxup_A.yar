
rule Trojan_Win32_Reproxup_A{
	meta:
		description = "Trojan:Win32/Reproxup.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {6d 6f 62 69 6c 65 2f 75 70 90 03 04 05 64 61 74 65 67 72 61 64 65 2e 70 68 70 3f 75 70 90 03 04 04 6c 69 76 65 6d 61 69 6e 90 00 } //05 00 
		$a_03_1 = {5c 52 65 61 6c 74 65 6b 73 90 01 01 00 00 ff ff ff ff 90 01 01 00 00 00 5c 6c 90 04 01 02 61 69 67 90 05 01 0a 30 31 32 33 34 35 36 37 38 39 2e 74 78 74 90 00 } //01 00 
		$a_01_2 = {72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c } //00 00  r_pref("network.proxy.autoconfig_url",
		$a_00_3 = {5d 04 00 00 4d fa } //02 80 
	condition:
		any of ($a_*)
 
}