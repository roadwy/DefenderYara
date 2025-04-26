
rule HackTool_Win32_Mimikatz_PTHA{
	meta:
		description = "HackTool:Win32/Mimikatz.PTHA,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 65 6b 75 72 6c 73 61 3a 3a 70 74 68 } //sekurlsa::pth  10
		$a_80_1 = {2f 75 73 65 72 3a } ///user:  1
		$a_80_2 = {2f 64 6f 6d 61 69 6e 3a } ///domain:  1
		$a_80_3 = {2f 6e 74 6c 6d 3a } ///ntlm:  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=11
 
}