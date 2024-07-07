
rule Trojan_BAT_Injuke_AAOR_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 11 04 06 11 04 91 20 5d 06 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 3a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}