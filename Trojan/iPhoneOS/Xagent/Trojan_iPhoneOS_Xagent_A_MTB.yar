
rule Trojan_iPhoneOS_Xagent_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/Xagent.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 31 39 38 2e 32 37 2e 36 34 2e 32 31 38 2f } //1 http://198.27.64.218/
		$a_00_1 = {76 61 72 2f 6d 6f 62 69 6c 65 2f 4c 69 62 72 61 72 79 2f 53 4d 53 2f 73 6d 73 2e 64 62 } //1 var/mobile/Library/SMS/sms.db
		$a_00_2 = {77 6f 72 6b 2f 49 4f 53 5f 50 52 4f 4a 45 43 54 2f 58 41 67 65 6e 74 2f 58 41 67 65 6e 74 2f 52 65 61 63 68 61 62 69 6c 69 74 79 2e 6d } //1 work/IOS_PROJECT/XAgent/XAgent/Reachability.m
		$a_00_3 = {66 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 2f 49 70 68 6f 6e 65 44 61 74 61 } //1 ftp://localhost/IphoneData
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}