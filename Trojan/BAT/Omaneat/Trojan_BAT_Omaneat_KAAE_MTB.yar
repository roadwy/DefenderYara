
rule Trojan_BAT_Omaneat_KAAE_MTB{
	meta:
		description = "Trojan:BAT/Omaneat.KAAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 1a 5a 59 7e ?? 00 00 04 1f 7a 7e ?? 00 00 04 1f 7a 93 05 61 20 ?? 00 00 00 5f 9d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}