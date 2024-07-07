
rule Trojan_BAT_Injuke_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 17 58 11 90 01 01 5d 13 90 01 01 02 08 07 91 11 90 01 01 61 08 11 90 01 01 91 59 28 90 01 04 13 90 01 01 08 07 11 90 01 01 28 90 01 04 d2 9c 07 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}