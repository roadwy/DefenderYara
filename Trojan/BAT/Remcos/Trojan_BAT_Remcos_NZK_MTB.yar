
rule Trojan_BAT_Remcos_NZK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 5d 91 06 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 06 8e 69 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}