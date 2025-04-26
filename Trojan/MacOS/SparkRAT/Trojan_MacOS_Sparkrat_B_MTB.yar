
rule Trojan_MacOS_Sparkrat_B_MTB{
	meta:
		description = "Trojan:MacOS/Sparkrat.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 65 78 65 63 43 6f 6d 6d 61 6e 64 } //1 Spark/client/core.execCommand
		$a_01_1 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 6d 6d 6f 6e 2e 28 2a 43 6f 6e 6e 29 2e 47 65 74 53 65 63 72 65 74 48 65 78 } //1 Spark/client/common.(*Conn).GetSecretHex
		$a_01_2 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 6b 69 6c 6c 54 65 72 6d 69 6e 61 6c } //1 Spark/client/core.killTerminal
		$a_01_3 = {53 70 61 72 6b 2f 63 6c 69 65 6e 74 2f 63 6f 72 65 2e 75 70 6c 6f 61 64 54 65 78 74 46 69 6c 65 } //1 Spark/client/core.uploadTextFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}