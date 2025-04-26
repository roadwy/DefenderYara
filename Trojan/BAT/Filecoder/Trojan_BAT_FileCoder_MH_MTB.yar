
rule Trojan_BAT_FileCoder_MH_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.MH!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6f 6e 6e 79 68 75 62 } //10 Donnyhub
		$a_01_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_2 = {44 65 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 DecryptionKey
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}