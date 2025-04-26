
rule Trojan_BAT_RedLine_KAP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d } //1
		$a_01_1 = {93 03 07 03 8e 69 5d 93 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}