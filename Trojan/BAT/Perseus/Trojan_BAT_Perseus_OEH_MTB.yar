
rule Trojan_BAT_Perseus_OEH_MTB{
	meta:
		description = "Trojan:BAT/Perseus.OEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 95 9e 11 04 08 09 9e 11 05 11 08 02 11 08 91 11 04 11 04 07 95 11 04 08 95 58 20 ff 00 00 00 5f 95 61 28 ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}