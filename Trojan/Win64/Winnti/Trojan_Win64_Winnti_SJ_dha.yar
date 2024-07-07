
rule Trojan_Win64_Winnti_SJ_dha{
	meta:
		description = "Trojan:Win64/Winnti.SJ!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 70 6c 69 74 4e 61 6d 65 41 6e 64 48 61 73 68 20 66 61 69 6c 65 64 } //1 SplitNameAndHash failed
		$a_01_1 = {43 72 65 64 65 6e 74 69 61 6c 73 20 6f 66 20 6e 65 77 20 70 72 6f 63 65 73 73 20 68 61 73 20 62 65 65 6e 20 63 68 61 6e 67 65 64 } //1 Credentials of new process has been changed
		$a_01_2 = {4c 55 49 44 3a 55 73 65 72 4e 61 6d 65 3a 4c 6f 67 6f 6e 44 6f 6d 61 69 6e 3a 4c 4d 68 61 73 68 3a 4e 54 68 61 73 68 } //1 LUID:UserName:LogonDomain:LMhash:NThash
		$a_01_3 = {52 65 61 64 69 6e 67 20 62 79 20 69 6e 6a 65 63 74 69 6e 67 20 63 6f 64 65 21 } //1 Reading by injecting code!
		$a_01_4 = {49 6e 6a 65 63 74 4d 65 6d 44 6c 6c 20 65 72 72 } //1 InjectMemDll err
		$a_01_5 = {47 65 74 50 69 64 42 79 4e 61 6d 65 20 25 73 20 72 65 74 20 65 72 72 } //1 GetPidByName %s ret err
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}