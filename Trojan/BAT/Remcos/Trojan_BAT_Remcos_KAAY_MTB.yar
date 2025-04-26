
rule Trojan_BAT_Remcos_KAAY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KAAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 [0-08] 5d [0-0f] 61 ?? ?? 59 20 00 02 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}