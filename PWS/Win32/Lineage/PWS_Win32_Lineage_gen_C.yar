
rule PWS_Win32_Lineage_gen_C{
	meta:
		description = "PWS:Win32/Lineage.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,36 00 32 00 12 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a } //5 Content-Disposition:
		$a_01_1 = {41 63 63 65 70 74 3a 20 69 6d 61 67 65 } //5 Accept: image
		$a_00_2 = {67 61 6d 65 2e 74 78 74 } //5 game.txt
		$a_00_3 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //5 Accept-Language: zh-cn
		$a_00_4 = {45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //5 Explorer_Server
		$a_01_5 = {48 6f 6f 6b 4f 66 66 } //5 HookOff
		$a_01_6 = {48 6f 6f 6b 4f 6e } //5 HookOn
		$a_01_7 = {73 65 72 76 65 72 2e 69 6e 69 } //5 server.ini
		$a_01_8 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //5 SeDebugPrivilege
		$a_00_9 = {54 69 61 6e 53 68 69 } //2 TianShi
		$a_00_10 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f 20 73 65 72 76 65 72 } //1 GetSystemInfo server
		$a_00_11 = {67 65 74 6d 65 6d 20 75 73 65 72 3a } //1 getmem user:
		$a_01_12 = {4c 69 6e 65 61 67 65 20 57 69 6e 64 6f 77 73 20 43 6c 69 65 6e 74 } //2 Lineage Windows Client
		$a_01_13 = {4d 61 70 6c 65 53 74 6f 72 79 43 } //1 MapleStoryC
		$a_01_14 = {73 65 72 76 65 72 4c 69 73 74 57 6e 64 } //2 serverListWnd
		$a_01_15 = {74 62 4d 61 69 6e 41 63 63 6f 75 6e 74 } //1 tbMainAccount
		$a_00_16 = {6c 6f 67 69 6e 5f 70 2e 61 73 70 } //1 login_p.asp
		$a_00_17 = {47 41 53 48 4c 6f 67 69 6e } //1 GASHLogin
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_00_9  & 1)*2+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_01_12  & 1)*2+(#a_01_13  & 1)*1+(#a_01_14  & 1)*2+(#a_01_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1) >=50
 
}