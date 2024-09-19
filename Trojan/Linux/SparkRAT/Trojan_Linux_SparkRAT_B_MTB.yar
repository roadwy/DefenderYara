
rule Trojan_Linux_SparkRAT_B_MTB{
	meta:
		description = "Trojan:Linux/SparkRAT.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 61 72 6b 2f 6d 6f 64 75 6c 65 73 2e 43 50 55 } //1 Spark/modules.CPU
		$a_01_1 = {64 65 73 6b 74 6f 70 2e 28 2a 73 63 72 65 65 6e 29 2e 63 61 70 74 75 72 65 } //1 desktop.(*screen).capture
		$a_01_2 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 73 65 72 76 69 63 65 2f 64 65 73 6b 74 6f 70 2e 4b 69 6c 6c 44 65 73 6b 74 6f 70 } //1 Spark/client/service/desktop.KillDesktop
		$a_01_3 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 6d 6d 6f 6e 2e 28 2a 43 6f 6e 6e 29 2e 47 65 74 53 65 63 72 65 74 48 65 78 } //1 Spark/client/common.(*Conn).GetSecretHex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}