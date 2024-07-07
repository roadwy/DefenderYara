
rule Trojan_BAT_RedLine_RDQ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 79 65 5f 54 68 30 6d 73 30 6c 76 30 73 } //1 Coye_Th0ms0lv0s
		$a_01_1 = {43 6f 79 65 5f 41 6e 37 77 65 72 } //1 Coye_An7wer
		$a_01_2 = {43 6f 79 65 5f 35 6f 75 6e 64 } //1 Coye_5ound
		$a_01_3 = {43 6f 79 65 5f 32 79 73 74 65 6d } //1 Coye_2ystem
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}