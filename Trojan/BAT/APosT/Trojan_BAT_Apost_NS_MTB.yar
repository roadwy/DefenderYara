
rule Trojan_BAT_Apost_NS_MTB{
	meta:
		description = "Trojan:BAT/Apost.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 c0 0f 00 00 28 06 00 00 0a 00 14 fe 06 03 00 00 06 73 07 00 00 0a 28 08 00 00 0a } //3
		$a_03_1 = {72 01 00 00 70 0a 28 ?? 00 00 0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 0c 07 72 ?? 00 00 70 28 ?? 00 00 0a 0d 14 13 04 12 05 fe 15 03 00 00 02 12 06 fe 15 04 00 00 02 73 ?? 00 00 0a 13 07 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}