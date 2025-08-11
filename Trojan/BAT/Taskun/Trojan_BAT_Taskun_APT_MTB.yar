
rule Trojan_BAT_Taskun_APT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.APT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {50 68 61 72 6d 61 43 61 72 65 20 4d 61 6e 61 67 65 72 2e 64 6c 6c } //1 PharmaCare Manager.dll
		$a_81_1 = {48 49 50 41 41 2d 63 6f 6d 70 6c 69 61 6e 74 20 70 68 61 72 6d 61 63 79 20 6d 61 6e 61 67 65 6d 65 6e 74 } //1 HIPAA-compliant pharmacy management
		$a_81_2 = {4d 65 64 54 65 63 68 20 53 6f 6c 75 74 69 6f 6e 73 20 49 6e 63 } //1 MedTech Solutions Inc
		$a_81_3 = {72 65 67 75 6c 61 74 65 64 20 68 65 61 6c 74 68 63 61 72 65 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 73 } //1 regulated healthcare environments
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}