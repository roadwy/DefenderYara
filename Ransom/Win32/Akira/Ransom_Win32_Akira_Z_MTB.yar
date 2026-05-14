
rule Ransom_Win32_Akira_Z_MTB{
	meta:
		description = "Ransom:Win32/Akira.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //1 akira_readme.txt
		$a_01_1 = {4e 75 6d 62 65 72 20 6f 66 20 74 68 72 65 61 64 73 20 74 6f 20 65 6e 63 72 79 70 74 20 3d } //1 Number of threads to encrypt =
		$a_01_2 = {77 72 69 74 65 5f 65 6e 63 72 79 70 74 5f 69 6e 66 6f 20 65 72 72 6f 72 3a } //1 write_encrypt_info error:
		$a_01_3 = {4c 6f 67 2d 25 64 2d 25 6d 2d 25 59 2d 25 48 2d 25 4d 2d 25 53 } //1 Log-%d-%m-%Y-%H-%M-%S
		$a_01_4 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 } //1 --encryption_path
		$a_01_5 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 65 72 63 65 6e 74 } //1 --encryption_percent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}