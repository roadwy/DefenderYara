
rule Trojan_MacOS_SparkRAT_A_MTB{
	meta:
		description = "Trojan:MacOS/SparkRAT.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 73 65 72 76 69 63 65 2f 66 69 6c 65 2e 55 70 6c 6f 61 64 46 69 6c 65 73 } //1 Spark/client/service/file.UploadFiles
		$a_01_1 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 73 65 72 76 69 63 65 2f 62 61 73 69 63 2e 53 68 75 74 64 6f 77 6e } //1 Spark/client/service/basic.Shutdown
		$a_01_2 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 6d 6d 6f 6e 2e 28 2a 43 6f 6e 6e 29 2e 47 65 74 53 65 63 72 65 74 } //1 Spark/client/common.(*Conn).GetSecret
		$a_01_3 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 73 65 72 76 69 63 65 2f 64 65 73 6b 74 6f 70 2e 4b 69 6c 6c 44 65 73 6b 74 6f 70 } //1 Spark/client/service/desktop.KillDesktop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}