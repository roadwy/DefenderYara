
rule HackTool_Linux_Keylogger_A_MTB{
	meta:
		description = "HackTool:Linux/Keylogger.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 3a 33 33 33 33 2f 75 70 6c 6f 61 64 } //1 ://localhost:3333/upload
		$a_00_1 = {2f 74 6d 70 2f 6b 65 79 2e 6c 6f 67 } //1 /tmp/key.log
		$a_00_2 = {70 79 78 5f 70 66 5f 39 6b 65 79 6c 6f 67 67 65 72 5f 73 65 6e 64 46 69 6c 65 73 } //1 pyx_pf_9keylogger_sendFiles
		$a_00_3 = {70 79 78 5f 70 66 5f 39 6b 65 79 6c 6f 67 67 65 72 5f 32 63 61 70 74 75 72 61 72 } //1 pyx_pf_9keylogger_2capturar
		$a_00_4 = {6b 65 79 6c 6f 67 67 65 72 2e 70 79 } //1 keylogger.py
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}