
rule Trojan_BAT_LummaStealer_ALM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 19 6c 11 1a 6c 5b 28 4b 00 00 0a b7 13 10 20 02 } //01 00 
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6e 00 20 00 75 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 45 00 7a 00 69 00 72 00 69 00 7a 00 27 00 73 00 } //00 00  This assembly is protected by an unregistered version of Eziriz's
	condition:
		any of ($a_*)
 
}