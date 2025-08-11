
rule Trojan_BAT_Cassandra_GPPD_MTB{
	meta:
		description = "Trojan:BAT/Cassandra.GPPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 9c 61 d2 81 01 00 00 01 11 ?? 1f ?? 91 13 10 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}