
rule Trojan_BAT_MSILZilla_MK_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_81_0 = {7b 30 7d 20 20 20 20 53 34 55 32 50 72 6f 78 79 54 61 72 67 65 74 20 20 20 20 20 20 3a 20 7b 31 7d } //15 {0}    S4U2ProxyTarget      : {1}
		$a_81_1 = {7b 30 7d 20 20 20 20 43 72 65 64 65 6e 74 69 61 6c 44 61 74 61 20 20 20 20 20 20 20 3a } //10 {0}    CredentialData       :
		$a_81_2 = {7b 30 7d 20 20 20 20 45 6e 63 72 79 70 74 69 6f 6e 54 79 70 65 20 20 20 20 20 20 20 3a 20 7b 31 7d } //5 {0}    EncryptionType       : {1}
		$a_81_3 = {7b 30 7d 44 65 63 72 79 70 74 65 64 20 50 41 43 20 20 20 20 20 20 20 20 20 20 20 20 3a } //3 {0}Decrypted PAC            :
		$a_81_4 = {5b 2a 5d 20 54 61 72 67 65 74 20 75 73 65 72 20 20 20 20 20 3a 20 7b 30 3a 78 7d } //2 [*] Target user     : {0:x}
	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=35
 
}