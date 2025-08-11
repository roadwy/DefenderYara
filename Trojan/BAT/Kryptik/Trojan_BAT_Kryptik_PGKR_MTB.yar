
rule Trojan_BAT_Kryptik_PGKR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.PGKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 02 00 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 72 01 00 00 70 72 07 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}