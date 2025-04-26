
rule Trojan_AndroidOS_BankerAgent_AG{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.AG,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 31 2e 61 70 69 6a 73 6f 6e 2e 78 79 7a 2f 61 70 70 2d 73 74 6f 72 65 3f 69 64 3d } //2 v1.apijson.xyz/app-store?id=
		$a_01_1 = {43 68 6f 6f 73 69 6e 67 20 73 75 62 73 63 72 69 70 74 69 6f 6e 20 62 61 73 65 64 20 53 4d 53 4d 61 6e 61 67 65 72 } //2 Choosing subscription based SMSManager
		$a_01_2 = {53 6d 73 20 66 6f 72 77 61 72 64 20 6f 6e 20 62 75 74 20 6e 75 6d 62 65 72 73 20 65 6d 70 74 79 3f } //2 Sms forward on but numbers empty?
		$a_01_3 = {53 6d 73 20 66 6f 72 77 61 72 64 20 6f 66 66 20 6f 72 20 6d 65 73 73 61 67 65 20 63 6f 6e 74 61 69 6e 20 65 6d 70 74 79 3f } //2 Sms forward off or message contain empty?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}