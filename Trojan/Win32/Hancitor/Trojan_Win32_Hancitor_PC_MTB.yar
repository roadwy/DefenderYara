
rule Trojan_Win32_Hancitor_PC_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffb4 00 ffffffb4 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 62 6f 75 74 5f 52 65 6d 6f 74 65 5f 4a 6f 62 73 2e 3c 2f 6d 61 6d 6c 3a 70 61 72 61 3e } //50 about_Remote_Jobs.</maml:para>
		$a_81_1 = {61 62 6f 75 74 5f 4a 6f 62 73 } //50 about_Jobs
		$a_81_2 = {57 69 6e 64 6f 77 73 20 50 6f 77 65 72 53 68 65 6c 6c } //50 Windows PowerShell
		$a_01_3 = {65 00 6e 00 61 00 62 00 6c 00 65 00 2d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 72 00 65 00 73 00 74 00 6f 00 72 00 65 00 20 00 2d 00 64 00 72 00 69 00 76 00 65 00 } //10 enable-computerrestore -drive
		$a_01_4 = {53 00 74 00 6f 00 70 00 2d 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 } //10 Stop-Computer
		$a_01_5 = {52 00 65 00 63 00 65 00 69 00 76 00 65 00 2d 00 4a 00 6f 00 62 00 2e 00 } //5 Receive-Job.
		$a_01_6 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 } //5 Connect
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=180
 
}