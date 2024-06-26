
rule VirTool_WinNT_Donk_ldr{
	meta:
		description = "VirTool:WinNT/Donk!ldr,SIGNATURE_TYPE_JAVAHSTR_EXT,22 00 20 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 63 65 72 74 2f 43 65 72 74 69 66 69 63 61 74 65 } //05 00  java/security/cert/Certificate
		$a_01_1 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 50 65 72 6d 69 73 73 69 6f 6e 73 } //05 00  java/security/Permissions
		$a_01_2 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 50 72 6f 74 65 63 74 69 6f 6e 44 6f 6d 61 69 6e } //05 00  java/security/ProtectionDomain
		$a_01_3 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 41 6c 6c 50 65 72 6d 69 73 73 69 6f 6e } //04 00  java/security/AllPermission
		$a_03_4 = {73 65 63 75 72 69 74 79 90 01 01 43 6f 64 65 53 6f 75 72 63 65 90 00 } //04 00 
		$a_03_5 = {72 65 66 6c 65 63 74 90 01 01 43 6f 6e 73 74 72 75 63 74 6f 72 90 00 } //01 00 
		$a_01_6 = {6e 65 74 2f 55 52 4c } //01 00  net/URL
		$a_01_7 = {6e 65 77 49 6e 73 74 61 6e 63 65 } //02 00  newInstance
		$a_01_8 = {7e 73 70 61 77 6e } //0a 00  ~spawn
		$a_01_9 = {12 12 b8 3a 19 b6 57 bb 59 bb 59 b7 } //00 00 
	condition:
		any of ($a_*)
 
}