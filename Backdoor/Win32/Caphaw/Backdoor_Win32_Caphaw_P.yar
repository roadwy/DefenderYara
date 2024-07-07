
rule Backdoor_Win32_Caphaw_P{
	meta:
		description = "Backdoor:Win32/Caphaw.P,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 68 69 6a 61 63 6b 63 66 67 2f 70 6c 75 67 69 6e 73 2f 70 6c 75 67 69 6e } //1 /hijackcfg/plugins/plugin
		$a_01_1 = {2f 68 69 6a 61 63 6b 63 66 67 2f 74 69 6d 65 72 5f 63 66 67 } //1 /hijackcfg/timer_cfg
		$a_01_2 = {00 42 6f 74 2e 64 6c 6c 00 } //2
		$a_01_3 = {3c 42 3e 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 3c 62 72 2f 3e 4f 4b 3c 2f 42 3e 3c 2f 42 4f 44 59 3e 3c 2f 48 54 4d 4c 3e } //2 <B>00000000000000000000000000<br/>OK</B></BODY></HTML>
		$a_03_4 = {8b 14 c6 89 94 8d 90 01 04 ff 85 90 01 04 33 c9 66 89 4c c6 06 8b 04 c6 3b 45 fc 76 03 89 45 fc 47 3b 7d 0c 0f 82 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2) >=7
 
}