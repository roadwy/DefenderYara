
rule PWS_BAT_Inssteal_A_MTB{
	meta:
		description = "PWS:BAT/Inssteal.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {66 6f 72 73 74 65 61 6c 61 6e 79 } //1 forstealany
		$a_81_1 = {68 61 63 6b 65 72 6d 65 } //1 hackerme
		$a_81_2 = {43 3a 5c 55 73 65 72 73 5c 68 61 63 6b 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 } //1 C:\Users\hacke\source\repos
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 69 6e 73 74 61 67 72 61 6d 2e 63 6f 6d 2f } //1 https://www.instagram.com/
		$a_81_4 = {49 43 72 65 64 65 6e 74 69 61 6c 73 42 79 48 6f 73 74 } //1 ICredentialsByHost
		$a_81_5 = {73 6d 74 70 2e 6c 69 76 65 2e 63 6f 6d } //1 smtp.live.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}