
rule Backdoor_Linux_FakeFile_A_xp{
	meta:
		description = "Backdoor:Linux/FakeFile.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 74 68 72 65 61 64 5f 63 61 6e 63 65 6c } //1 pthread_cancel
		$a_00_1 = {66 69 6c 65 20 22 25 73 22 } //1 file "%s"
		$a_00_2 = {63 68 6d 6f 64 20 37 37 37 } //1 chmod 777
		$a_00_3 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_00_4 = {25 73 2e 62 61 6b } //1 %s.bak
		$a_00_5 = {74 61 72 20 7a 78 66 20 22 25 73 22 20 2d 43 20 22 25 73 22 } //1 tar zxf "%s" -C "%s"
		$a_00_6 = {2f 2e 62 61 73 68 5f 70 72 6f 66 69 6c 65 } //1 /.bash_profile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}