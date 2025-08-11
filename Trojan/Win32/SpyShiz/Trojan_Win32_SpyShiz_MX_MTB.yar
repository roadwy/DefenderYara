
rule Trojan_Win32_SpyShiz_MX_MTB{
	meta:
		description = "Trojan:Win32/SpyShiz.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 6f 69 6c 5c 66 65 65 74 5c 53 65 76 65 6e 5c 53 65 6e 64 5c 47 61 74 68 65 72 5c 44 69 76 69 64 65 72 61 69 6c 2e 70 64 62 } //1 c:\oil\feet\Seven\Send\Gather\Dividerail.pdb
		$a_01_1 = {6c 00 69 00 73 00 74 00 65 00 6e 00 20 00 61 00 62 00 6f 00 76 00 65 00 } //1 listen above
		$a_01_2 = {66 00 61 00 6d 00 69 00 6c 00 79 00 63 00 6f 00 75 00 6c 00 64 00 20 00 63 00 6f 00 73 00 74 00 } //1 familycould cost
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_SpyShiz_MX_MTB_2{
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