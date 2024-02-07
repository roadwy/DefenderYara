
rule Trojan_Win32_Infistov_QQ_MTB{
	meta:
		description = "Trojan:Win32/Infistov.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {74 65 6d 70 5f 64 69 72 } //03 00  temp_dir
		$a_81_1 = {73 65 61 72 63 68 5f 70 61 74 68 } //03 00  search_path
		$a_81_2 = {49 6e 73 74 61 6c 6c 65 72 46 69 6c 65 54 61 6b 65 4f 76 65 72 2e 70 64 62 } //03 00  InstallerFileTakeOver.pdb
		$a_81_3 = {43 6f 6e 76 65 72 74 53 74 72 69 6e 67 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 54 6f 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 57 } //03 00  ConvertStringSecurityDescriptorToSecurityDescriptorW
		$a_81_4 = {50 72 6f 64 75 63 74 44 69 72 } //03 00  ProductDir
		$a_81_5 = {4c 6f 63 6b 69 74 } //03 00  Lockit
		$a_81_6 = {49 6d 70 65 72 73 6f 6e 61 74 65 4c 6f 67 67 65 64 4f 6e 55 73 65 72 } //00 00  ImpersonateLoggedOnUser
	condition:
		any of ($a_*)
 
}