
rule Trojan_BAT_Tedy_AMME_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 61 90 02 0c 5d 91 59 20 00 01 00 00 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}