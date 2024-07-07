
rule Trojan_Win32_Aptdrop_E{
	meta:
		description = "Trojan:Win32/Aptdrop.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 45 43 6f 6e 73 6f 6c 65 5c 42 61 63 6b 65 6e 64 5c 52 65 6c 65 61 73 65 5c 70 61 79 6c 6f 61 64 2e 70 64 62 } //1 PEConsole\Backend\Release\payload.pdb
		$a_01_1 = {77 73 3a 2f 2f 34 35 2e 33 32 2e 31 31 37 2e 31 31 36 3a 34 34 33 50 41 64 65 66 61 75 6c 74 50 68 74 74 70 } //1 ws://45.32.117.116:443PAdefaultPhttp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}