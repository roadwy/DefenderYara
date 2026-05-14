
rule Trojan_Win32_Fragtor_SXB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 08 00 00 "
		
	strings :
		$a_80_0 = {5c 31 2e 64 6c 6c } //\1.dll  10
		$a_80_1 = {2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 64 65 6c 61 79 20 30 30 30 30 3a 33 30 } ///sc onlogon /delay 0000:30  10
		$a_01_2 = {42 4c 41 43 4b 4c 49 53 54 5f 49 50 7c 7c } //10 BLACKLIST_IP||
		$a_01_3 = {4d 44 35 5f 44 45 54 45 43 54 7c 7c } //10 MD5_DETECT||
		$a_01_4 = {42 4c 41 43 4b 4c 49 53 54 5f 44 41 54 41 } //2 BLACKLIST_DATA
		$a_01_5 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_01_6 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //1 winlogon.exe
		$a_01_7 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskmgr.exe
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=35
 
}