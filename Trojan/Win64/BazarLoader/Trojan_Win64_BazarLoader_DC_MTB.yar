
rule Trojan_Win64_BazarLoader_DC_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //03 00  DllRegisterServer
		$a_81_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //03 00  PluginInit
		$a_81_2 = {52 75 6e 4f 62 6a 65 63 74 } //03 00  RunObject
		$a_81_3 = {42 6d 74 70 7a 68 6c 44 68 65 64 61 78 74 43 73 64 75 70 64 79 77 62 61 62 } //03 00  BmtpzhlDhedaxtCsdupdywbab
		$a_81_4 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 4d 70 44 72 69 76 65 72 } //00 00  \Registry\Machine\System\CurrentControlSet\Services\MpDriver
	condition:
		any of ($a_*)
 
}