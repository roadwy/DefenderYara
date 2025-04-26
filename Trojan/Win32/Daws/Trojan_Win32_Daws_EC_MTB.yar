
rule Trojan_Win32_Daws_EC_MTB{
	meta:
		description = "Trojan:Win32/Daws.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 6f 70 79 66 69 6c 65 } //1 copyfile
		$a_81_1 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Windows\CurrentVersion\Run
		$a_81_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 45 6e 61 62 6c 65 4c 55 41 } //1 CurrentVersion\Policies\System\EnableLUA
		$a_81_3 = {57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 Windows NT\CurrentVersion\Winlogon
		$a_81_4 = {53 65 52 65 6d 6f 74 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeRemoteShutdownPrivilege
		$a_81_5 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 WScript.Shell
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}