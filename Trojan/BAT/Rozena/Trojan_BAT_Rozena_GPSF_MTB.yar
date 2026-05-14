
rule Trojan_BAT_Rozena_GPSF_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GPSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f 62 6a 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 43 6c 6f 73 65 48 61 6e 64 6c 65 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}