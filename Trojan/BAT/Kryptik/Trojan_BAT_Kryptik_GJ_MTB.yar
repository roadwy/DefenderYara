
rule Trojan_BAT_Kryptik_GJ_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 28 90 02 04 13 06 11 06 72 90 02 15 13 07 11 07 14 18 8d 90 02 04 13 08 11 08 16 28 90 02 09 16 9a 28 90 02 04 a2 11 08 17 11 04 a2 11 08 6f 90 00 } //02 00 
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  02 00 
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  02 00 
		$a_80_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  00 00 
	condition:
		any of ($a_*)
 
}