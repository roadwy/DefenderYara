
rule Trojan_BAT_ClipBanker_PSTB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PSTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 20 54 93 ca 40 28 90 01 01 00 00 06 02 20 8a 92 ca 40 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0a 06 2c 07 06 73 37 00 00 0a 2a 14 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}