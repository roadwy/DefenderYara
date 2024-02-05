
rule Trojan_BAT_Redcap_MBDD_MTB{
	meta:
		description = "Trojan:BAT/Redcap.MBDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 64 39 32 39 63 30 30 33 2d 65 36 32 39 2d 34 36 35 36 2d 62 34 31 33 2d 34 38 37 37 38 34 34 66 36 64 36 35 } //01 00 
		$a_01_1 = {4d 79 57 69 33 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}