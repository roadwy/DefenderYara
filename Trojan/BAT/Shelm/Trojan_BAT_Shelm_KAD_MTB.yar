
rule Trojan_BAT_Shelm_KAD_MTB{
	meta:
		description = "Trojan:BAT/Shelm.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 11 09 11 11 91 11 0b 28 90 01 01 00 00 0a 61 d2 9c 11 11 17 58 13 11 11 11 09 8e 69 32 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}