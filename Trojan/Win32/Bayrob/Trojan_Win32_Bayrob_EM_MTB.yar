
rule Trojan_Win32_Bayrob_EM_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 4b 4d 71 7a 4b 49 41 4c 71 64 72 75 5a 6f 6b 53 65 45 } //1 tKMqzKIALqdruZokSeE
		$a_81_1 = {77 42 53 6d 76 58 4c } //1 wBSmvXL
		$a_81_2 = {6b 50 49 4b 5a 78 44 64 4c 64 51 51 52 74 76 63 75 } //1 kPIKZxDdLdQQRtvcu
		$a_81_3 = {4f 50 62 43 46 77 62 6e 6b 50 71 4d 77 47 44 48 7a 73 79 69 69 41 43 46 61 42 4f } //1 OPbCFwbnkPqMwGDHzsyiiACFaBO
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}