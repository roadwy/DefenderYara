
rule Trojan_Win32_Vemply_DA_MTB{
	meta:
		description = "Trojan:Win32/Vemply.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {2f 63 6f 6e 66 69 67 2f 67 6a 63 2e 74 78 74 } //1 /config/gjc.txt
		$a_81_1 = {6d 6f 62 69 6c 65 2e 79 61 6e 67 6b 65 64 75 6f 2e 63 6f 6d } //1 mobile.yangkeduo.com
		$a_81_2 = {69 74 65 6d 2e 74 61 6f 62 61 6f 2e 63 6f 6d } //1 item.taobao.com
		$a_81_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_81_5 = {56 35 6d 2e 63 6f 6d } //1 V5m.com
		$a_81_6 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //1 WinHttpCrackUrl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}