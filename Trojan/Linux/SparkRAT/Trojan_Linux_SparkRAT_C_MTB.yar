
rule Trojan_Linux_SparkRAT_C_MTB{
	meta:
		description = "Trojan:Linux/SparkRAT.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 73 65 72 76 69 63 65 2f 73 63 72 65 65 6e 73 68 6f 74 2e 47 65 74 53 63 72 65 65 6e 73 68 6f 74 } //3 Spark/client/service/screenshot.GetScreenshot
		$a_01_1 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 6d 6d 6f 6e 2e 28 2a 43 6f 6e 6e 29 2e 53 65 6e 64 44 61 74 61 } //3 Spark/client/common.(*Conn).SendData
		$a_01_2 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 73 65 72 76 69 63 65 2f 64 65 73 6b 74 6f 70 2e 4b 69 6c 6c 44 65 73 6b 74 6f 70 } //1 Spark/client/service/desktop.KillDesktop
		$a_01_3 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 67 65 74 44 65 73 6b 74 6f 70 } //1 Spark/client/core.getDesktop
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}