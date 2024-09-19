
rule Trojan_BAT_Remcos_AMAU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 91 09 09 07 95 09 11 ?? 95 58 20 ff 00 00 00 5f 95 d2 61 d2 9c 11 ?? 17 6a 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}