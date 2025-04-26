
rule Backdoor_Win32_Rewdulon_B{
	meta:
		description = "Backdoor:Win32/Rewdulon.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 10 00 04 70 ff 34 6c 70 ff 80 0c 00 5e ?? ?? ?? 00 71 6c ff 3c 6c 70 ff 6c 10 00 fc 58 6c 6c ff 71 78 ff 2f 70 ff 6c 78 ff fc 52 1c 30 00 14 6c 74 ff 0a ?? ?? ?? 00 3c 14 f5 } //3
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 65 00 72 00 } //1 SOFTWARE\SystemControler
		$a_01_2 = {5c 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 } //1 \Remote Startup\
		$a_01_3 = {4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 53 00 4d 00 54 00 50 00 2e 00 65 00 78 00 65 00 } //1 OutlookSMTP.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}