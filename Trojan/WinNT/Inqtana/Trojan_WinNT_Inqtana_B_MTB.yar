
rule Trojan_WinNT_Inqtana_B_MTB{
	meta:
		description = "Trojan:WinNT/Inqtana.B!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 6f 70 65 6e 62 75 6e 64 6c 65 2e 70 6c 69 73 74 } //1 Library/LaunchAgents/com.openbundle.plist
		$a_00_1 = {4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 70 77 6e 65 64 2e 70 6c 69 73 74 } //1 Library/LaunchAgents/com.pwned.plist
		$a_00_2 = {2f 77 30 72 6d 2d 73 75 70 70 6f 72 74 2e 74 67 7a } //1 /w0rm-support.tgz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}