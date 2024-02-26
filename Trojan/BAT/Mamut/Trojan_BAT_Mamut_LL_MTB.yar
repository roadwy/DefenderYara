
rule Trojan_BAT_Mamut_LL_MTB{
	meta:
		description = "Trojan:BAT/Mamut.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 17 58 07 8e b7 90 01 05 07 09 93 0c 07 09 07 09 17 58 93 9d 07 09 17 58 08 9d 00 09 18 58 0d 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}