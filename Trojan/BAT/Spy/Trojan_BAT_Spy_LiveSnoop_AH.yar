
rule Trojan_BAT_Spy_LiveSnoop_AH{
	meta:
		description = "Trojan:BAT/Spy.LiveSnoop.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {4c 69 76 65 53 6e 6f 6f 70 5f 41 67 65 6e 74 } //LiveSnoop_Agent  3
		$a_80_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  3
		$a_80_2 = {73 65 74 5f 53 68 75 74 64 6f 77 6e 53 74 79 6c 65 } //set_ShutdownStyle  3
		$a_80_3 = {73 65 74 5f 53 68 6f 77 49 6e 54 61 73 6b 62 61 72 } //set_ShowInTaskbar  3
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  3
		$a_80_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //ToBase64String  3
		$a_80_6 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //HttpWebRequest  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}