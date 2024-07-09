
rule Trojan_BAT_Seraph_AS_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? ?? ?? 06 13 00 38 00 00 00 00 28 ?? ?? ?? 0a 11 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 01 } //1
		$a_01_1 = {02 8e 69 17 59 13 03 38 0e 00 00 00 11 00 11 03 3c 4b 00 00 00 38 17 00 00 00 38 ed ff ff ff 38 49 00 00 00 02 11 00 02 11 03 91 9c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}