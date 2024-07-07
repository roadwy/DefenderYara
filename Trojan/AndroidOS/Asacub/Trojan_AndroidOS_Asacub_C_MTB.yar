
rule Trojan_AndroidOS_Asacub_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Asacub.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 6c 6f 63 6b 53 65 72 76 64 66 67 64 67 64 } //1 BlockServdfgdgd
		$a_01_1 = {70 6f 6f 6d 61 64 6d } //1 poomadm
		$a_01_2 = {64 64 2f 61 53 2f 64 64 2f 73 73 64 66 67 66 64 67 64 2f 73 6d 73 73 69 78 66 67 64 67 64 2f 48 65 61 64 6c 65 73 73 53 6d 73 53 65 6e 64 53 65 72 76 69 63 } //1 dd/aS/dd/ssdfgfdgd/smssixfgdgd/HeadlessSmsSendServic
		$a_01_3 = {53 6d 73 6d 6e 64 } //1 Smsmnd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}