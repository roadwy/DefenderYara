
rule Trojan_Win32_SpyShiz_MX_MTB{
	meta:
		description = "Trojan:Win32/SpyShiz.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 00 65 00 62 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 } //1 websocket.dll
		$a_01_1 = {31 00 30 00 2e 00 30 00 2e 00 31 00 37 00 31 00 33 00 34 00 2e 00 31 00 } //1 10.0.17134.1
		$a_01_2 = {6c 00 69 00 73 00 74 00 65 00 6e 00 20 00 61 00 62 00 6f 00 76 00 65 00 } //1 listen above
		$a_01_3 = {66 00 61 00 6d 00 69 00 6c 00 79 00 63 00 6f 00 75 00 6c 00 64 00 20 00 63 00 6f 00 73 00 74 00 } //1 familycould cost
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}