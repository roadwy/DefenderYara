
rule Trojan_BAT_Remcos_CZM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.CZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 2c 39 06 2c 36 06 28 ?? ?? ?? 0a 0b 16 0c 28 ?? ?? ?? 0a 0d 2b 21 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}