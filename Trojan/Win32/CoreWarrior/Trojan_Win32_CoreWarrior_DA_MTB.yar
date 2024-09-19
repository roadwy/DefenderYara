
rule Trojan_Win32_CoreWarrior_DA_MTB{
	meta:
		description = "Trojan:Win32/CoreWarrior.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 69 62 67 63 6a 5f 73 2e 64 6c 6c } //1 libgcj_s.dll
		$a_81_1 = {77 61 20 72 69 66 61 69 65 6e 20 79 61 6e 6a 65 20 76 31 2e 30 } //1 wa rifaien yanje v1.0
		$a_81_2 = {68 74 74 70 3a 2f 2f 77 65 63 61 6e 2e 68 61 73 74 68 65 2e 74 65 63 68 6e 6f } //10 http://wecan.hasthe.techno
		$a_81_3 = {6c 6f 67 79 2f 75 70 6c 6f 61 64 } //1 logy/upload
		$a_81_4 = {43 4f 4e 4e 45 43 54 5f 4f 4e 4c 59 20 69 73 20 72 65 71 75 69 72 65 64 21 } //1 CONNECT_ONLY is required!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}