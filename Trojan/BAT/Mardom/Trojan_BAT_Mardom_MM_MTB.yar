
rule Trojan_BAT_Mardom_MM_MTB{
	meta:
		description = "Trojan:BAT/Mardom.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 72 01 00 00 70 28 05 00 00 0a 72 33 00 00 70 28 05 00 00 0a 6f 06 00 00 0a 0d 73 07 00 00 0a 13 04 07 73 08 00 00 0a 13 05 } //3
		$a_01_1 = {11 06 11 04 6f 0a 00 00 0a 11 04 6f 0b 00 00 0a 0b dd 2b 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}