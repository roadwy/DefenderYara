
rule Trojan_Win32_Clipbanker_RW_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 69 74 63 6f 69 6e 63 61 73 68 3a } //1 bitcoincash:
		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //1 GetStartupInfoW
		$a_81_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 61 6e 61 73 74 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 63 6c 65 61 70 65 72 5c 52 65 6c 65 61 73 65 5c 63 6c 65 61 70 65 72 2e 70 64 62 } //10 C:\Users\anast\source\repos\cleaper\Release\cleaper.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*10) >=14
 
}