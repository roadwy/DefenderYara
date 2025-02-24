
rule Trojan_BAT_VenomRAT_SPCB_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.SPCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 6f ?? 00 00 0a 17 73 0f 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0a de 0a 09 2c 06 09 6f ?? 00 00 0a dc } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}