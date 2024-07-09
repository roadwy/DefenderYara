
rule Trojan_BAT_Shelma_SXP_MTB{
	meta:
		description = "Trojan:BAT/Shelma.SXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 18 59 20 ?? ?? ?? 00 5f d2 9c 06 17 58 0a 06 02 8e 69 32 e7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}