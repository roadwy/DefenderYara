
rule Trojan_Win64_DonutLoader_SJY_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.SJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_81_1 = {4c 6f 61 64 65 72 } //1 Loader
		$a_81_2 = {68 74 74 70 3a 2f 2f 39 34 2e 31 35 34 2e 33 35 2e 31 31 35 2f 75 73 65 72 5f 70 72 6f 66 69 6c 65 73 5f 70 68 6f 74 6f 2f 63 70 74 63 68 62 75 69 6c 64 2e 62 69 6e } //1 http://94.154.35.115/user_profiles_photo/cptchbuild.bin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}