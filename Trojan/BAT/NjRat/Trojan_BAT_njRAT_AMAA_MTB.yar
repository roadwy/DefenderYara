
rule Trojan_BAT_njRAT_AMAA_MTB{
	meta:
		description = "Trojan:BAT/njRAT.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 6f 0b 00 00 0a 00 08 18 6f 90 01 01 00 00 0a 00 08 18 6f 90 01 01 00 00 0a 00 08 6f 90 01 01 00 00 0a 0d 09 06 16 06 8e 69 6f 90 01 01 00 00 0a 13 04 08 6f 90 01 01 00 00 0a 00 28 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a 13 05 2b 00 11 05 2a 90 00 } //01 00 
		$a_80_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //RijndaelManaged  01 00 
		$a_80_2 = {42 4a 50 52 56 34 42 4d } //BJPRV4BM  01 00 
		$a_80_3 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //TripleDESCryptoServiceProvider  00 00 
	condition:
		any of ($a_*)
 
}