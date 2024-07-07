
rule Trojan_Win32_Donbot_A{
	meta:
		description = "Trojan:Win32/Donbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 6d 61 69 6c 3d 25 73 } //1 email=%s
		$a_00_1 = {50 4f 53 54 20 2f 67 61 74 65 77 61 79 2f 69 6e 64 65 78 20 48 54 54 50 2f 31 2e 30 } //1 POST /gateway/index HTTP/1.0
		$a_03_2 = {8b 44 24 10 30 0c 06 57 43 e8 90 01 04 59 3b d8 72 e7 8b 44 24 10 f6 14 06 50 46 e8 90 01 04 59 3b f0 72 c7 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Donbot_A_2{
	meta:
		description = "Trojan:Win32/Donbot.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 42 4c 3a 20 25 6c 75 0d 0a } //1
		$a_01_1 = {7b 42 41 53 45 36 34 45 4d 41 49 4c 7d } //1 {BASE64EMAIL}
		$a_01_2 = {7b 71 70 5f 73 74 61 72 74 7d } //1 {qp_start}
		$a_01_3 = {4d 61 78 2d 54 68 72 65 61 64 73 3a 20 } //1 Max-Threads: 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}