
rule Trojan_Win32_Cionrox_B{
	meta:
		description = "Trojan:Win32/Cionrox.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {b9 81 00 00 00 e8 ?? ?? ?? ?? 8b d8 85 db 7e 10 8d 95 ?? ?? ff ff 8b cb 8b 45 ?? 8b 30 ff 56 10 85 db 7f bb } //1
		$a_01_1 = {75 71 8d 55 e8 b8 1a 00 00 00 e8 } //1
		$a_00_2 = {2f 2f 69 6e 66 65 63 2e 70 68 70 } //1 //infec.php
		$a_00_3 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 20 22 68 74 74 70 3a 2f 2f } //1 user_pref("network.proxy.autoconfig_url", "http://
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}