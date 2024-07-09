
rule Trojan_BAT_Remcos_NL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 6f 0d ?? ?? ?? 03 58 20 00 ?? ?? ?? 5d 0c 08 16 2f 08 08 20 00 ?? ?? ?? 58 0c 06 07 08 d1 9d 07 17 58 0b 07 02 6f 0c ?? ?? ?? 32 d2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}