
rule HackTool_MacOS_keylogger_D_MTB{
	meta:
		description = "HackTool:MacOS/keylogger.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 6c 6f 67 2f 6b 65 79 73 74 72 6f 6b 65 2e 6c 6f 67 } //1 /var/log/keystroke.log
		$a_00_1 = {45 52 52 4f 52 3a 20 55 6e 61 62 6c 65 20 74 6f 20 63 72 65 61 74 65 20 65 76 65 6e 74 20 74 61 70 } //1 ERROR: Unable to create event tap
		$a_00_2 = {4b 65 79 6c 6f 67 67 69 6e 67 20 68 61 73 20 62 65 67 75 6e } //1 Keylogging has begun
		$a_00_3 = {45 52 52 4f 52 3a 20 55 6e 61 62 6c 65 20 74 6f 20 6f 70 65 6e 20 6c 6f 67 20 66 69 6c 65 2e 20 45 6e 73 75 72 65 20 74 68 61 74 20 79 6f 75 20 68 61 76 65 20 74 68 65 20 70 72 6f 70 65 72 20 70 65 72 6d 69 73 73 69 6f 6e 73 } //1 ERROR: Unable to open log file. Ensure that you have the proper permissions
		$a_00_4 = {43 47 45 76 65 6e 74 54 61 70 43 72 65 61 74 65 } //1 CGEventTapCreate
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}