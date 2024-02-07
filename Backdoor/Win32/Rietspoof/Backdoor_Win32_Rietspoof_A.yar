
rule Backdoor_Win32_Rietspoof_A{
	meta:
		description = "Backdoor:Win32/Rietspoof.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 57 6f 72 6b 5c 64 32 4f 64 37 73 34 33 5c 72 65 76 53 68 65 6c 6c 5c 66 77 73 68 65 6c 6c 2d 6d 61 73 74 65 72 5c 52 65 6c 65 61 73 65 5c 66 77 73 68 65 6c 6c 2e 70 64 62 } //01 00  F:\Work\d2Od7s43\revShell\fwshell-master\Release\fwshell.pdb
		$a_01_1 = {31 00 30 00 34 00 2e 00 32 00 34 00 38 00 2e 00 31 00 37 00 37 00 2e 00 31 00 38 00 38 00 } //00 00  104.248.177.188
	condition:
		any of ($a_*)
 
}