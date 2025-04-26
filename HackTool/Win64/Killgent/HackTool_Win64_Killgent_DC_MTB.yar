
rule HackTool_Win64_Killgent_DC_MTB{
	meta:
		description = "HackTool:Win64/Killgent.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 5c 53 65 72 76 69 63 65 4d 6f 75 73 65 } //1 .\ServiceMouse
		$a_81_1 = {63 6d 64 20 2f 63 20 64 72 69 76 65 72 71 75 65 72 79 } //1 cmd /c driverquery
		$a_81_2 = {64 65 6c 65 74 69 6e 67 20 65 78 65 2f 64 6c 6c 2f 73 79 73 2f 63 6f 6d } //1 deleting exe/dll/sys/com
		$a_81_3 = {41 6e 74 69 76 69 72 75 73 20 54 65 72 6d 69 6e 61 74 6f 72 } //1 Antivirus Terminator
		$a_81_4 = {44 69 73 61 62 6c 65 20 70 72 6f 63 65 73 73 20 50 49 44 } //1 Disable process PID
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}