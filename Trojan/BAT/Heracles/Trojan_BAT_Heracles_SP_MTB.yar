
rule Trojan_BAT_Heracles_SP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 90 01 03 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df 90 00 } //01 00 
		$a_01_1 = {53 00 6e 00 6b 00 66 00 61 00 65 00 62 00 63 00 6e 00 6a 00 61 00 6f 00 70 00 6a 00 6e 00 6a 00 77 00 77 00 6a 00 2e 00 49 00 6f 00 61 00 78 00 64 00 6b 00 6c 00 6c 00 78 00 6f 00 72 00 73 00 69 00 76 00 63 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}