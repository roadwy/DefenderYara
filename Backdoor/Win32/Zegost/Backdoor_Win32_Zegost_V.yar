
rule Backdoor_Win32_Zegost_V{
	meta:
		description = "Backdoor:Win32/Zegost.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 2d 61 67 65 6e 74 3a 20 72 65 64 61 70 70 31 65 20 48 74 74 70 20 50 72 6f 78 79 20 76 25 2e 32 66 25 73 20 25 73 } //1 Proxy-agent: redapp1e Http Proxy v%.2f%s %s
		$a_00_1 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 %systemroot%\system32\svchost.exe -k netsvcs
		$a_01_2 = {43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 00 00 7e 4d 48 7a } //1
		$a_01_3 = {5f 64 6c 6c 5f 44 65 6c 65 74 65 5f 4d 65 5f 5f 2e 62 61 74 } //1 _dll_Delete_Me__.bat
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}