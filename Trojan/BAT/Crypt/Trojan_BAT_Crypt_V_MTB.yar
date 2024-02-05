
rule Trojan_BAT_Crypt_V_MTB{
	meta:
		description = "Trojan:BAT/Crypt.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {25 16 07 7b 90 01 03 04 a2 25 17 07 7b 90 01 03 04 a2 25 18 07 7b 90 01 03 04 a2 25 19 07 7b 90 01 03 04 a2 25 1a 07 7b 90 01 03 04 a2 25 1b 07 7b 90 01 03 04 a2 25 1c 07 7b 90 01 03 04 a2 25 1d 07 7b 90 01 03 04 a2 25 1e 07 7b 90 01 03 04 a2 28 90 01 03 0a a2 a2 6f 90 01 03 0a 26 2a 90 00 } //01 00 
		$a_00_1 = {52 6f 63 6b 5f 50 61 70 65 72 5f 53 63 69 73 73 6f 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}