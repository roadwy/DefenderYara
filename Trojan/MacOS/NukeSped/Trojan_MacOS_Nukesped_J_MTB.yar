
rule Trojan_MacOS_Nukesped_J_MTB{
	meta:
		description = "Trojan:MacOS/Nukesped.J!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 47 6f 6f 67 6c 65 4d 73 67 53 74 61 74 75 73 2e 70 64 66 } //1 /tmp/GoogleMsgStatus.pdf
		$a_01_1 = {2f 74 6d 70 2f 4e 65 74 4d 73 67 53 74 61 74 75 73 } //1 /tmp/NetMsgStatus
		$a_01_2 = {6e 65 74 62 6f 74 75 72 6c } //1 netboturl
		$a_01_3 = {67 6f 6f 67 6c 65 62 6f 74 75 72 6c } //1 googleboturl
		$a_01_4 = {62 75 79 32 78 2e 63 6f 6d } //1 buy2x.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}