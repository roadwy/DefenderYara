
rule Trojan_BAT_Bladabindi_SC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 48 45 4c 4c 2e 70 64 62 } //1 SHELL.pdb
		$a_81_1 = {53 48 45 4c 4c 2e 65 78 65 } //1 SHELL.exe
		$a_81_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_3 = {4d 6f 6e 69 74 6f 72 } //1 Monitor
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 78 44 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 48 45 4c 4c 5c 53 48 45 4c 4c 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 48 45 4c 4c 2e 70 64 62 } //1 C:\Users\xD\source\repos\SHELL\SHELL\obj\Release\SHELL.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}