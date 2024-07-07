
rule Backdoor_Linux_CloudSnooper_gen_A{
	meta:
		description = "Backdoor:Linux/CloudSnooper.gen!A!!Cloudsnooper.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6c 6f 75 64 2e 6e 65 77 73 6f 66 6e 70 2e 63 6f 6d } //5 cloud.newsofnp.com
		$a_81_1 = {73 73 6c 2e 6e 65 77 73 6f 66 6e 70 2e 63 6f 6d } //5 ssl.newsofnp.com
		$a_81_2 = {36 32 2e 31 31 33 2e 32 35 35 2e 31 38 } //5 62.113.255.18
		$a_81_3 = {38 39 2e 33 33 2e 32 34 36 2e 31 31 31 } //5 89.33.246.111
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5) >=5
 
}