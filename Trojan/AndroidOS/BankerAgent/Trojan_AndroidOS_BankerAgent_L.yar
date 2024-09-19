
rule Trojan_AndroidOS_BankerAgent_L{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.L,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 6e 65 77 2f 61 63 74 69 76 65 63 68 65 63 6b 2e 70 68 70 } //2 apinew/activecheck.php
		$a_01_1 = {73 6d 73 6c 69 73 74 6e 65 72 2f 50 61 63 6b 61 67 65 52 65 6d 6f 76 61 6c 52 65 63 65 69 76 65 72 } //2 smslistner/PackageRemovalReceiver
		$a_01_2 = {74 68 61 6e 6b 79 6f 75 73 63 72 65 65 6e 2f 54 68 61 6e 6b 79 6f 75 53 63 72 65 65 6e } //2 thankyouscreen/ThankyouScreen
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}