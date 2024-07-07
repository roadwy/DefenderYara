
rule Trojan_BAT_NanoBot_QA_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 01 00 00 00 27 00 00 00 17 00 00 00 01 00 00 00 0b 00 00 00 02 00 00 00 14 00 00 00 27 00 00 00 05 00 00 00 03 00 00 00 01 00 00 00 03 } //10
		$a_80_1 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //HttpWebResponse  3
		$a_80_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //HttpWebRequest  3
		$a_80_3 = {53 79 73 74 65 6d 2e 44 65 70 6c 6f 79 6d 65 6e 74 2e 49 6e 74 65 72 6e 61 6c 2e 49 73 6f 6c 61 74 69 6f 6e } //System.Deployment.Internal.Isolation  3
		$a_80_4 = {53 74 6f 72 65 4f 70 65 72 61 74 69 6f 6e 53 65 74 44 65 70 6c 6f 79 6d 65 6e 74 4d 65 74 61 64 61 74 61 } //StoreOperationSetDeploymentMetadata  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}