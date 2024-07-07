
rule Trojan_Win32_Goriadu_AA_dll{
	meta:
		description = "Trojan:Win32/Goriadu.AA!dll,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 0b 00 00 "
		
	strings :
		$a_01_0 = {55 70 64 61 74 65 2d 4c 6f 63 6b 2d 33 66 61 66 39 38 } //1 Update-Lock-3faf98
		$a_01_1 = {2e 6c 30 30 38 36 2e 63 6f 6d 2e 63 6e } //1 .l0086.com.cn
		$a_01_2 = {2e 30 32 6c 2e 63 6e } //1 .02l.cn
		$a_01_3 = {63 3a 5c 6c 6f 67 2d 73 65 72 76 65 72 2d 31 2e 74 78 74 } //1 c:\log-server-1.txt
		$a_01_4 = {77 77 77 2e 30 31 30 63 6f 6d 2e 63 6e 2f 63 6f 75 6e 74 } //1 www.010com.cn/count
		$a_01_5 = {5c 4d 79 54 6f 6f 6c 73 48 65 6c 70 5c } //1 \MyToolsHelp\
		$a_01_6 = {63 6d 73 73 63 2e 64 6c 6c } //1 cmssc.dll
		$a_01_7 = {75 2e 67 6f 67 6c 65 2e 63 6e 2f 64 65 66 61 75 6c 74 } //1 u.gogle.cn/default
		$a_01_8 = {5c 62 61 69 64 75 5c 74 6f 68 6f 6d 65 2e 65 78 65 } //1 \baidu\tohome.exe
		$a_00_9 = {5c 4d 79 49 45 44 61 74 61 5c 00 00 53 79 73 } //1
		$a_01_10 = {62 72 75 64 6f 2e 64 61 74 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1) >=6
 
}