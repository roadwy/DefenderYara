
rule Trojan_BAT_Bladabindi_SWERRER_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SWERRER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c5 81 c0 93 00 00 00 b9 ca 05 00 00 ba 90 01 04 30 10 40 49 0f 85 f6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}