
rule Trojan_BAT_Remcos_AMMI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 [0-19] 8e 69 5d 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}