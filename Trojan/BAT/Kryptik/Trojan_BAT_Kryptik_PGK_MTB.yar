
rule Trojan_BAT_Kryptik_PGK_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 33 00 00 70 72 35 00 00 70 17 8d ?? 00 00 01 25 16 1f 25 9d 28 ?? 00 00 0a 7e ?? 00 00 04 25 2d 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}