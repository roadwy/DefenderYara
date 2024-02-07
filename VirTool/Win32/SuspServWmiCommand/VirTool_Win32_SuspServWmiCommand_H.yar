
rule VirTool_Win32_SuspServWmiCommand_H{
	meta:
		description = "VirTool:Win32/SuspServWmiCommand.H,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //f6 ff  \ProgramData\
		$a_00_2 = {2e 00 64 00 6c 00 6c 00 } //00 00  .dll
	condition:
		any of ($a_*)
 
}