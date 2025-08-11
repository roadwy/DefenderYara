
rule Trojan_BAT_Kryptik_PGKM_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.PGKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 40 00 00 04 2d 67 02 17 7d 40 00 00 04 02 7b 3f 00 00 04 2d 29 02 73 73 01 00 06 7d 3f 00 00 04 02 7b 3f 00 00 04 1f 13 7d c1 01 00 04 02 7b 3f 00 00 04 02 28 ?? 00 00 0a 7d c2 01 00 04 02 7b 3f 00 00 04 28 ?? ?? 00 06 2d 22 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}