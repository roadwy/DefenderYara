
rule Trojan_BAT_Heracles_AMAG_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 [0-0f] 61 [0-0f] 17 58 08 5d 13 [0-0f] 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}