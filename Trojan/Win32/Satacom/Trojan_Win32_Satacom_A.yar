
rule Trojan_Win32_Satacom_A{
	meta:
		description = "Trojan:Win32/Satacom.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_03_0 = {fe c2 0f b6 d2 8b 4c ?? ?? 8d 04 0b 0f b6 d8 8b 44 ?? ?? 89 44 ?? ?? 89 4c ?? ?? 02 c8 0f b6 c1 8b 4d f8 8a 44 ?? ?? 30 04 ?? ?? 3b ?? fc 7c d0 } //2
		$a_00_1 = {7c 50 49 50 45 7c 76 62 4f 58 } //1 |PIPE|vbOX
		$a_02_2 = {25 73 5c 73 76 63 68 6f 73 74 2e 25 73 [0-10] 2e 64 61 74 } //1
		$a_00_3 = {63 72 79 70 74 6f 5f 64 6f 6d 61 69 6e } //1 crypto_domain
		$a_00_4 = {70 6f 73 74 62 61 63 6b 5f 75 72 6c } //1 postback_url
		$a_00_5 = {65 78 65 63 75 74 65 5f 6d 65 74 68 6f 64 } //1 execute_method
		$a_00_6 = {6e 65 65 64 5f 63 61 70 74 63 68 61 } //1 need_captcha
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}