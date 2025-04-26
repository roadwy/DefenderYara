
rule Trojan_Win32_VB_OJ{
	meta:
		description = "Trojan:Win32/VB.OJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 79 00 73 00 77 00 73 00 6f 00 63 00 6b 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 \syswsock32.dll
		$a_00_1 = {5c 00 42 00 69 00 6e 00 5c 00 57 00 73 00 6f 00 63 00 6b 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 \Bin\Wsock32.dll
		$a_00_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 54 00 65 00 6e 00 63 00 65 00 6e 00 74 00 5c 00 51 00 51 00 } //1 SOFTWARE\Tencent\QQ
		$a_03_3 = {8d 4d c8 51 53 e8 ?? ?? ?? ?? ff d6 8b 55 c8 52 6a 00 6a 38 e8 ?? ?? ?? ?? 89 45 b4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}