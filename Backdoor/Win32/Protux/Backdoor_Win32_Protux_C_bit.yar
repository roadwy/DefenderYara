
rule Backdoor_Win32_Protux_C_bit{
	meta:
		description = "Backdoor:Win32/Protux.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 55 10 30 14 08 40 3b 45 0c 72 f4 } //2
		$a_03_1 = {8b 45 08 03 c1 80 30 ?? 41 3b 4d 0c 7c f2 } //2
		$a_01_2 = {55 73 65 72 20 47 65 74 20 49 45 20 50 72 6f 78 79 20 46 61 69 6c 65 64 } //1 User Get IE Proxy Failed
		$a_01_3 = {57 69 6e 48 74 74 70 47 65 74 49 45 50 72 6f 78 79 43 6f 6e 66 69 67 20 65 72 72 6f 72 3a 25 64 } //1 WinHttpGetIEProxyConfig error:%d
		$a_01_4 = {7e 44 46 33 62 62 73 2e 74 6d 70 } //1 ~DF3bbs.tmp
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}