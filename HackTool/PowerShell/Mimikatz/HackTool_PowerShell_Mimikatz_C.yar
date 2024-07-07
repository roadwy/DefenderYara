
rule HackTool_PowerShell_Mimikatz_C{
	meta:
		description = "HackTool:PowerShell/Mimikatz.C,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffca 00 ffffffca 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //50 powershell
		$a_02_1 = {69 00 65 00 78 00 90 02 03 28 00 90 00 } //50
		$a_00_2 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //50 net.webclient
		$a_00_3 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //50 .downloadstring(
		$a_00_4 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 6d 00 69 00 6d 00 69 00 6b 00 69 00 74 00 74 00 65 00 6e 00 7a 00 } //2 invoke-mimikittenz
		$a_00_5 = {2f 00 6d 00 69 00 6d 00 69 00 6b 00 69 00 74 00 74 00 65 00 6e 00 7a 00 2f 00 } //2 /mimikittenz/
	condition:
		((#a_00_0  & 1)*50+(#a_02_1  & 1)*50+(#a_00_2  & 1)*50+(#a_00_3  & 1)*50+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=202
 
}