
rule Trojan_AndroidOS_BrowBot_D_MTB{
	meta:
		description = "Trojan:AndroidOS/BrowBot.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 64 61 74 61 5f 32 38 2f 69 6e 73 74 61 6c 6c 5f 32 38 2e 70 68 70 } //1 /data_28/install_28.php
		$a_01_1 = {2f 64 61 74 61 5f 32 38 2f 73 6d 73 61 70 69 5f 32 38 2e 70 68 70 } //1 /data_28/smsapi_28.php
		$a_01_2 = {63 72 65 64 65 6e 74 69 61 6c 73 4c 61 75 6e 63 68 65 72 5f } //1 credentialsLauncher_
		$a_01_3 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f } //1 senderphone_
		$a_01_4 = {73 6f 75 72 63 65 61 70 69 73 61 70 70 2e 63 6f 6d } //1 sourceapisapp.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}