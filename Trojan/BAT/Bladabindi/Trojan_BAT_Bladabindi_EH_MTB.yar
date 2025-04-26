
rule Trojan_BAT_Bladabindi_EH_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 08 07 08 8e 69 5d 91 61 02 07 17 58 02 8e 69 5d 91 59 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}