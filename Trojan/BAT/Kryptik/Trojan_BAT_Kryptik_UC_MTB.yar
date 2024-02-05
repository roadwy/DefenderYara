
rule Trojan_BAT_Kryptik_UC_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.UC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 20 00 03 72 90 01 04 6f 90 01 04 13 21 11 21 19 8d 90 01 04 25 16 7e 90 01 04 a2 25 17 7e 90 01 04 a2 25 18 72 90 01 04 a2 28 90 01 04 26 20 90 01 04 0a 2b 00 06 2a 90 00 } //02 00 
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //FromBase64CharArray  02 00 
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  00 00 
	condition:
		any of ($a_*)
 
}