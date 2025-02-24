
rule Trojan_BAT_Remcos_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 20 ff 00 00 00 5f [0-0f] 58 20 00 01 00 00 5e [0-1e] 05 03 04 03 91 0e ?? 0e ?? 95 61 d2 9c 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}