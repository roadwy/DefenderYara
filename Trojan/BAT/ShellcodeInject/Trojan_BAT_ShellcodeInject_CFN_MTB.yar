
rule Trojan_BAT_ShellcodeInject_CFN_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeInject.CFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {51 75 65 75 65 20 6f 66 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 2e 20 50 6f 6f 6c 50 61 72 74 79 20 53 75 63 63 65 73 73 21 } //1 Queue of target process. PoolParty Success!
		$a_81_1 = {6d 61 6c 69 63 69 6f 75 73 20 54 50 5f 4a 4f 42 } //1 malicious TP_JOB
		$a_81_2 = {73 61 63 72 69 66 69 63 69 61 6c 20 65 64 67 65 20 70 72 6f 63 65 73 73 20 77 69 6c 6c 20 62 65 20 63 72 65 61 74 65 64 20 66 6f 72 20 74 68 65 20 69 6e 6a 65 63 74 69 6f 6e } //1 sacrificial edge process will be created for the injection
		$a_81_3 = {57 72 69 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 73 74 61 72 74 20 72 6f 75 74 69 6e 65 20 61 64 64 72 65 73 73 } //1 Writing shellcode to start routine address
		$a_81_4 = {77 6f 72 6b 65 72 20 66 61 63 74 6f 72 79 20 73 74 61 72 74 20 72 6f 75 74 69 6e 65 2c 20 62 79 74 65 73 57 72 69 74 74 65 6e } //1 worker factory start routine, bytesWritten
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}