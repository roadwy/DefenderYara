
rule Trojan_BAT_Tiny_EH_MTB{
	meta:
		description = "Trojan:BAT/Tiny.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 2e 54 61 73 6b 73 } //1 System.Threading.Tasks
		$a_01_1 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 50 65 72 6d 69 73 73 69 6f 6e 73 } //1 System.Security.Permissions
		$a_01_2 = {67 65 74 5f 52 65 73 75 6c 74 } //1 get_Result
		$a_01_3 = {48 74 74 70 43 6c 69 65 6e 74 } //1 HttpClient
		$a_01_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 6c 00 65 00 61 00 6e 00 69 00 6e 00 67 00 2e 00 68 00 6f 00 6d 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 } //1 http://cleaning.homesecuritypc.com/packages
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}