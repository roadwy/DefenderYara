
rule Trojan_BAT_Donut_GPSF_MTB{
	meta:
		description = "Trojan:BAT/Donut.GPSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 00 6b 65 72 6e 65 6c 33 32 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 00 4f 70 65 6e 54 68 72 65 61 64 00 00 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}