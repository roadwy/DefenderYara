
rule Trojan_Win32_SpyNoon_RT_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 49 73 64 6a 65 6b 2e 64 6c 6c } //1 \Isdjek.dll
		$a_81_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //1 ShellExecuteExA
		$a_81_2 = {49 6d 61 67 65 4c 69 73 74 5f 44 65 73 74 72 6f 79 } //1 ImageList_Destroy
		$a_81_3 = {47 78 6b 65 6f 78 6b 7a 73 } //1 Gxkeoxkzs
		$a_81_4 = {6c 6f 61 64 70 65 72 66 2e 64 6c 6c } //1 loadperf.dll
		$a_81_5 = {50 72 6f 6a 65 63 74 35 31 2e 64 6c 6c } //1 Project51.dll
		$a_81_6 = {53 79 73 4c 69 73 74 56 69 65 77 33 32 } //1 SysListView32
		$a_81_7 = {5c 73 6f 6d 65 74 68 69 6e 67 2e 69 6e 69 } //1 \something.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}