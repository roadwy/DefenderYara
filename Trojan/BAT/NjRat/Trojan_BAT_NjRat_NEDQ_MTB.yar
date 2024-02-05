
rule Trojan_BAT_NjRat_NEDQ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 33 62 39 65 36 37 36 32 2d 65 32 65 34 2d 34 61 33 36 2d 39 61 34 66 2d 39 63 37 65 35 36 35 63 63 33 37 65 } //05 00 
		$a_01_1 = {4f 62 66 75 73 63 61 74 65 64 5c 4f 62 66 75 73 63 61 74 65 64 5c 65 78 70 6c 6f 72 65 72 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}