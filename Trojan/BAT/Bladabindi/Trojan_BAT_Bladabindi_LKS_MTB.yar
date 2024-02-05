
rule Trojan_BAT_Bladabindi_LKS_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.LKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 08 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 09 17 5f 17 33 07 11 0a 11 04 58 13 0a 08 1b 64 08 1f 1b 62 60 1d 5a 0c 09 17 64 09 1f 1f 62 60 0d 11 09 17 58 13 09 11 09 6a 20 00 2e 08 00 6a 32 bc } //00 00 
	condition:
		any of ($a_*)
 
}