
rule TrojanDropper_Win32_Koobface_E{
	meta:
		description = "TrojanDropper:Win32/Koobface.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 20 2f 25 73 20 63 6f 70 79 20 22 25 73 22 20 22 25 73 2e 65 78 65 22 } //1 %s /%s copy "%s" "%s.exe"
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 25 73 22 20 2f 76 20 74 70 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 73 20 2f 66 } //1 reg add "HKLM\%s" /v tp /t REG_SZ /d %s /f
		$a_01_2 = {72 45 25 73 61 64 25 73 68 25 73 6d 25 73 73 54 25 73 5c 43 25 73 72 65 25 73 6f 25 73 6f 25 73 54 25 73 65 25 73 63 45 53 25 73 73 46 69 25 73 72 } //1 rE%sad%sh%sm%ssT%s\C%sre%so%so%sT%se%scES%ssFi%sr
		$a_01_3 = {25 25 70 25 73 52 41 25 73 6c 45 53 25 25 25 73 44 44 6e 25 73 6c 25 73 } //1 %%p%sRA%slES%%%sDDn%sl%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}