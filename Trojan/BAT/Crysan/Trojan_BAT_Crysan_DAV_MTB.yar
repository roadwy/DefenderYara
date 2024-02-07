
rule Trojan_BAT_Crysan_DAV_MTB{
	meta:
		description = "Trojan:BAT/Crysan.DAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 06 11 04 8e 69 5d 91 09 06 91 61 d2 6f 90 01 01 00 00 0a 06 0c 08 17 58 0a 06 09 8e 69 32 df 90 00 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}