
rule Trojan_Win64_Rootkit_EH_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 4c 24 38 48 8d 54 24 48 41 bc 00 d0 00 00 45 33 c0 48 8b cb c7 44 24 28 40 00 00 00 c7 44 24 20 00 10 00 00 4c 89 64 24 38 } //10
		$a_81_1 = {77 6f 72 6b 73 70 61 63 65 34 5c 6c 6f 63 6b 5c 68 70 73 61 66 65 5c 73 72 63 5c 73 79 73 5c 6f 62 6a 66 72 65 5f 77 69 6e 37 5f 61 6d 64 36 34 5c 61 6d 64 36 34 5c 68 70 73 61 66 65 2e 70 64 62 } //1 workspace4\lock\hpsafe\src\sys\objfre_win7_amd64\amd64\hpsafe.pdb
		$a_81_2 = {52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 4d 70 44 72 69 76 65 72 } //1 Registry\Machine\System\CurrentControlSet\Services\MpDriver
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}