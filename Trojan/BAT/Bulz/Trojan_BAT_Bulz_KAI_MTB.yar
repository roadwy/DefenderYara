
rule Trojan_BAT_Bulz_KAI_MTB{
	meta:
		description = "Trojan:BAT/Bulz.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 91 08 08 11 0a 84 95 08 11 08 84 95 d7 6e 20 ff 00 00 00 6a 5f 84 95 61 86 9c 11 0d 17 d6 13 0d 2b 8a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}