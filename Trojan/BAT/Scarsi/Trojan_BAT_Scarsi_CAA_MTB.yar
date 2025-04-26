
rule Trojan_BAT_Scarsi_CAA_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.CAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 25 00 00 0a 1f 10 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 08 18 58 0c 08 06 1a 2c f9 32 da 07 6f 28 00 00 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}