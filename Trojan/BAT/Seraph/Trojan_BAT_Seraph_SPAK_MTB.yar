
rule Trojan_BAT_Seraph_SPAK_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}