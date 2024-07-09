
rule Trojan_BAT_Disabler_NN_MTB{
	meta:
		description = "Trojan:BAT/Disabler.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 41 ?? ?? ?? ?? ?? ?? ?? ?? 00 0a 9c 08 18 58 0c 08 06 32 e4 07 0d de 1f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}