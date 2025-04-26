
rule Trojan_BAT_Remcos_FWC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 07 09 07 8e 69 5d 91 06 09 91 61 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}