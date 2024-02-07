
rule Trojan_Win32_Tinxy_A{
	meta:
		description = "Trojan:Win32/Tinxy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 85 30 fe ff ff 68 ff 01 0f 00 50 ff 75 f8 ff 15 90 01 03 00 3b c3 89 45 f4 74 12 53 53 50 90 00 } //01 00 
		$a_01_1 = {61 64 64 20 70 6f 72 74 6f 70 65 6e 69 6e 67 20 38 30 20 74 69 6e 79 70 72 6f 78 79 20 45 4e 41 42 4c 45 } //01 00  add portopening 80 tinyproxy ENABLE
		$a_01_2 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e } //01 00  user_pref("network.
		$a_01_3 = {68 74 74 70 3d 31 32 37 2e 30 2e 30 2e 31 3a 39 30 39 30 } //00 00  http=127.0.0.1:9090
	condition:
		any of ($a_*)
 
}