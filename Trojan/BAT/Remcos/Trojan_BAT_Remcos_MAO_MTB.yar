
rule Trojan_BAT_Remcos_MAO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 e0 95 58 20 ff 00 00 00 5f e0 95 61 28 ?? ?? ?? 0a 9c 11 06 17 6a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}