
rule Trojan_Win32_Rozena_EH_MTB{
	meta:
		description = "Trojan:Win32/Rozena.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {d9 74 24 f4 5b 31 c9 66 b9 3b 55 31 53 1c 83 c3 04 03 53 18 e2 } //05 00 
		$a_01_1 = {d9 74 24 f4 5e 2b c9 66 b9 3b 55 83 ee fc 31 5e 13 03 5e 13 e2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Rozena_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Rozena.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 52 56 57 6e 5a 6c 62 46 56 33 56 32 74 6b 56 56 4a 59 5a 7a 4a 56 56 6c 4a 44 56 6b 5a 5a 65 46 4e 75 54 6d 46 57 65 6b 45 78 56 31 5a 6b 55 6d 51 78 53 6e 4a } //01 00  FRVWnZlbFV3V2tkVVJYZzJVVlJDVkZZeFNuTmFWekExV1ZkUmQxSnJ
		$a_01_1 = {75 64 57 35 77 59 57 4e 72 4b 43 55 6f 62 54 41 70 4b 53 35 6d 61 58 4a 7a 64 43 6b 3d } //01 00  udW5wYWNrKCUobTApKS5maXJzdCk=
		$a_01_2 = {43 72 65 61 74 65 46 69 6c 65 41 } //01 00  CreateFileA
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_4 = {5a 65 75 73 } //01 00  Zeus
		$a_01_5 = {61 70 72 5f 73 6f 63 6b 65 74 5f 72 65 63 76 } //00 00  apr_socket_recv
	condition:
		any of ($a_*)
 
}