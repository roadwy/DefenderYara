
rule Backdoor_Win32_Mirai_A{
	meta:
		description = "Backdoor:Win32/Mirai.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 1d 8d 48 ff 8a 40 ff 84 c0 74 0a 3c ff 74 06 fe c8 88 01 eb 09 51 e8 } //01 00 
		$a_01_1 = {2f 76 65 72 2e 74 78 74 } //01 00  /ver.txt
		$a_01_2 = {2f 75 70 64 61 74 65 2e 74 78 74 } //01 00  /update.txt
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 3a 38 38 38 38 2f } //01 00  http://%s:8888/
		$a_01_4 = {5c 6d 73 69 6e 66 6f 2e 65 78 65 } //01 00  \msinfo.exe
		$a_01_5 = {2f 64 65 6c 65 74 65 20 2f 66 20 2f 74 6e 20 6d 73 69 6e 66 6f } //00 00  /delete /f /tn msinfo
		$a_00_6 = {7e 15 00 00 } //99 8c 
	condition:
		any of ($a_*)
 
}