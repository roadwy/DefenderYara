
rule Trojan_BAT_Zusy_SWQR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SWQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 91 7e 09 00 00 04 09 7e 09 00 00 04 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 07 8e 69 32 df } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_BAT_Zusy_SWQR_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.SWQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 11 0d 11 09 11 0d 91 11 0b 11 0d 11 0b 8e 69 5d 91 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 09 8e 69 32 dc } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}