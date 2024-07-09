
rule Trojan_BAT_Injuke_JBAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.JBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 91 18 28 ?? 09 00 06 28 ?? 08 00 06 28 ?? 09 00 06 59 d2 9c 09 19 28 ?? 09 00 06 58 0d 09 07 8e 69 32 d9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}