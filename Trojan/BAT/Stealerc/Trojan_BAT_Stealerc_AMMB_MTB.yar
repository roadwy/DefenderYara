
rule Trojan_BAT_Stealerc_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 11 0d 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 01 11 11 91 61 d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}