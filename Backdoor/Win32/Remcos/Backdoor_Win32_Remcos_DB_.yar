
rule Backdoor_Win32_Remcos_DB_{
	meta:
		description = "Backdoor:Win32/Remcos.DB!!Remcos.gen!DB,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 } //Remcos_Mutex  1
		$a_80_1 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64 } //Keylogger Started  1
		$a_80_2 = {4d 75 74 65 78 5f 52 65 6d 57 61 74 63 68 64 6f 67 } //Mutex_RemWatchdog  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}