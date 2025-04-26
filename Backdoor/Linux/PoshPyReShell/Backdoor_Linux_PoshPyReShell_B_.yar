
rule Backdoor_Linux_PoshPyReShell_B_{
	meta:
		description = "Backdoor:Linux/PoshPyReShell.B!!PoshPyReShell.B,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {70 79 6b 65 79 3d } //1 pykey=
		$a_81_1 = {70 79 68 61 73 68 3d } //1 pyhash=
		$a_81_2 = {73 65 72 76 65 72 63 6c 65 61 6e } //1 serverclean
		$a_81_3 = {61 57 49 79 4c 6e 56 79 62 47 39 77 5a 57 34 6f 63 69 6b 37 61 48 52 74 62 44 31 79 5a 58 4d 75 63 6d 56 68 5a 43 67 70 4f 33 67 39 5a 47 56 6a 63 6e 6c 77 64 43 68 72 5a 58 6b 73 49 47 68 30 62 57 77 70 4c 6e 4a 7a 64 48 4a 70 63 43 67 6e 58 44 41 6e 4b 54 74 6c 65 47 56 6a 4b 47 4a 68 63 32 55 32 4e 43 35 69 4e 6a 52 6b 5a 57 4e 76 5a 47 55 6f 65 43 6b 70 43 67 3d 3d } //1 aWIyLnVybG9wZW4ocik7aHRtbD1yZXMucmVhZCgpO3g9ZGVjcnlwdChrZXksIGh0bWwpLnJzdHJpcCgnXDAnKTtleGVjKGJhc2U2NC5iNjRkZWNvZGUoeCkpCg==
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}