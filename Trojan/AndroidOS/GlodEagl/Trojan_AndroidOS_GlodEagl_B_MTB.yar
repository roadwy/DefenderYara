
rule Trojan_AndroidOS_GlodEagl_B_MTB{
	meta:
		description = "Trojan:AndroidOS/GlodEagl.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 72 6f 6a 61 6e 2f 6e 65 74 57 72 6f 6b } //5 Lcom/example/trojan/netWrok
		$a_01_1 = {73 65 6e 64 54 65 6c 65 67 72 61 6d } //1 sendTelegram
		$a_01_2 = {4c 63 6f 6d 2f 73 61 72 6b 75 79 2f 75 69 2f 53 70 6c 61 73 68 41 63 74 69 76 69 74 79 } //5 Lcom/sarkuy/ui/SplashActivity
		$a_01_3 = {2f 67 65 74 74 61 73 6b 2e 70 68 70 } //1 /gettask.php
		$a_01_4 = {2f 73 61 76 65 67 70 73 2e 70 68 70 } //1 /savegps.php
		$a_01_5 = {2f 72 65 63 69 76 65 66 69 6c 65 2e 70 68 70 } //1 /recivefile.php
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}