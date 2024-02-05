
rule Trojan_BAT_Redcap_RDD_MTB{
	meta:
		description = "Trojan:BAT/Redcap.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 64 33 62 66 35 34 31 2d 37 66 63 66 2d 34 62 64 65 2d 62 32 34 33 2d 66 39 64 38 37 37 62 62 31 38 62 39 } //01 00 
		$a_01_1 = {53 65 6e 64 55 73 62 4b 65 79 } //01 00 
		$a_01_2 = {53 65 6e 64 69 6e 66 6f } //01 00 
		$a_01_3 = {63 68 65 63 6b 45 6e 61 62 6c 65 4c 55 41 } //00 00 
	condition:
		any of ($a_*)
 
}