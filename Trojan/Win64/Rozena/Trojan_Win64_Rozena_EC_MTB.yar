
rule Trojan_Win64_Rozena_EC_MTB{
	meta:
		description = "Trojan:Win64/Rozena.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {45 54 57 20 70 61 74 63 68 65 64 20 21 } //1 ETW patched !
		$a_81_1 = {4f 70 65 6e 69 6e 67 20 61 20 68 61 6e 64 6c 65 20 6f 6e 20 73 70 6f 6f 6c 73 76 20 70 72 6f 63 65 73 73 } //1 Opening a handle on spoolsv process
		$a_81_2 = {50 72 65 70 61 72 69 6e 67 20 74 68 65 20 76 65 6e 6f 6d 61 } //1 Preparing the venoma
		$a_81_3 = {53 68 65 6c 6c 63 6f 64 65 20 65 78 65 63 75 74 65 64 } //1 Shellcode executed
		$a_81_4 = {42 65 67 69 6e 6e 69 6e 67 20 73 65 6c 66 2d 64 65 6c 65 74 69 6f 6e 20 70 72 6f 63 65 73 73 } //1 Beginning self-deletion process
		$a_81_5 = {52 65 6e 61 6d 69 6e 67 20 3a 24 44 41 54 41 20 74 6f 20 25 73 } //1 Renaming :$DATA to %s
		$a_81_6 = {44 65 6c 65 74 69 6e 67 20 62 69 6e 61 72 79 20 66 69 6c 65 } //1 Deleting binary file
		$a_81_7 = {56 65 6e 6f 6d 61 2e 70 64 62 } //1 Venoma.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}