
rule Trojan_Win32_WebHijack_A_dll{
	meta:
		description = "Trojan:Win32/WebHijack.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 c1 e0 06 25 c0 00 00 00 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 8a 55 ?? 88 11 } //3
		$a_00_1 = {8a d1 c0 ea 02 02 c0 80 e2 0c 02 c2 c0 e9 06 02 c1 88 04 3e 83 c6 01 3b f5 72 d2 } //3
		$a_00_2 = {57 65 62 48 69 6a 61 63 6b } //1 WebHijack
		$a_00_3 = {5c 77 65 62 73 61 66 65 2e 73 79 73 } //1 \websafe.sys
		$a_00_4 = {5c 53 61 66 65 42 6f 6f 74 5c 4d 69 6e 69 6d 61 6c 5c 25 73 2e 73 79 73 } //1 \SafeBoot\Minimal\%s.sys
		$a_00_5 = {49 73 44 72 69 76 65 72 52 75 6e 6e 69 6e 67 } //1 IsDriverRunning
		$a_00_6 = {4c 6f 61 64 43 6f 6e 66 69 67 } //1 LoadConfig
		$a_00_7 = {63 75 74 69 6c 5f 64 72 69 76 65 72 5f 4f 70 65 6e 44 65 76 69 63 65 } //1 cutil_driver_OpenDevice
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}