
rule Trojan_Win32_Rootkit_EK_MTB{
	meta:
		description = "Trojan:Win32/Rootkit.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 40 57 89 45 f8 8d 45 f8 50 53 8d 45 f4 50 ff 75 08 } //10
		$a_81_1 = {63 6e 7a 7a 5f 75 72 6c } //5 cnzz_url
		$a_81_2 = {73 65 61 72 63 68 69 6e 67 5f 6d 61 67 69 63 5f 75 72 6c } //5 searching_magic_url
		$a_81_3 = {38 2e 38 2e 38 2e 38 } //1 8.8.8.8
		$a_81_4 = {68 70 73 61 66 65 2e 70 64 62 } //1 hpsafe.pdb
		$a_81_5 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 Explorer.exe
		$a_81_6 = {72 65 63 6f 75 6e 74 } //1 recount
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=23
 
}