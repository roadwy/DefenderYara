
rule Trojan_BAT_Dothetuk_NN_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 5e d1 0d 11 0e 11 06 5a 11 08 58 20 ?? ?? ?? ?? 5e d1 13 06 11 0b 17 58 13 0b 1f 11 13 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}