
rule Trojan_BAT_Heracles_GPAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 00 06 04 6f ?? ?? ?? 06 0d 09 61 73 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}