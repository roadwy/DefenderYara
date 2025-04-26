
rule Trojan_BAT_DonutLoader_EAEP_MTB{
	meta:
		description = "Trojan:BAT/DonutLoader.EAEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 12 02 7b 0f 00 00 04 28 07 00 00 0a 2c 0a 12 02 7b 08 00 00 04 0a 2b 0a 07 12 02 28 ?? ?? ?? 06 2d dd } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}