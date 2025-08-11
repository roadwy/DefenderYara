
rule Trojan_BAT_NjRAT_GPPG_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.GPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 04 91 13 05 00 07 06 11 05 20 05 b9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}