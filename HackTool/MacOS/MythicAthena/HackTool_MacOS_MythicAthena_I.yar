
rule HackTool_MacOS_MythicAthena_I{
	meta:
		description = "HackTool:MacOS/MythicAthena.I,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {41 74 68 65 6e 61 2e 64 6c 6c } //1 Athena.dll
		$a_00_1 = {40 5f 67 73 73 5f 61 63 71 75 69 72 65 5f 63 72 65 64 5f 77 69 74 68 5f 70 61 73 73 77 6f 72 64 } //1 @_gss_acquire_cred_with_password
		$a_00_2 = {68 61 63 6b 69 73 68 43 6c 61 73 73 4e 61 6d 65 } //1 hackishClassName
		$a_00_3 = {40 5f 6b 69 6c 6c } //1 @_kill
		$a_00_4 = {40 5f 67 65 74 68 6f 73 74 6e 61 6d 65 } //1 @_gethostname
		$a_00_5 = {40 5f 67 65 74 65 75 69 64 } //1 @_geteuid
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}