
rule Trojan_BAT_Keylogger_KK_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 63 72 65 65 6e 73 68 6f 74 54 72 69 67 67 65 72 57 6f 72 64 } //1 screenshotTriggerWord
		$a_01_1 = {70 72 6f 63 65 73 73 53 74 65 61 6c 5f 54 69 63 6b } //2 processSteal_Tick
		$a_01_2 = {63 6c 69 70 62 6f 61 72 64 4c 6f 67 67 65 72 5f 54 69 63 6b } //3 clipboardLogger_Tick
		$a_81_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //4 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_4 = {46 54 50 20 4c 6f 67 2e 74 78 74 } //5 FTP Log.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5) >=15
 
}