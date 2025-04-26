
rule Trojan_BAT_Keylogger_AYB_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 00 53 00 48 00 20 00 2d 00 20 00 4b 00 65 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 2d 00 20 00 4c 00 4f 00 47 00 } //2 SSH - Key Logger - LOG
		$a_01_1 = {53 53 48 5f 4b 65 79 6c 6f 67 67 65 72 5f 53 74 75 62 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 SSH_Keylogger_Stub.Form1.resources
		$a_01_2 = {24 32 35 66 30 33 39 34 34 2d 39 32 39 34 2d 34 32 30 39 2d 38 63 64 63 2d 30 34 31 37 35 35 62 65 66 62 39 37 } //1 $25f03944-9294-4209-8cdc-041755befb97
		$a_01_3 = {61 64 64 74 6f 53 74 61 72 74 75 70 } //1 addtoStartup
		$a_01_4 = {6b 65 79 62 6f 61 72 64 48 6f 6f 6b 50 72 6f 63 } //1 keyboardHookProc
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}