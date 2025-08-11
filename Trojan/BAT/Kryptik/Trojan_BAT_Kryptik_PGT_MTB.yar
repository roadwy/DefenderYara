
rule Trojan_BAT_Kryptik_PGT_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {94 58 20 00 01 00 00 5d 94 fe 0e 0e 00 fe 0c 07 00 fe 0c 0c 00 fe 09 00 00 fe 0c 0c 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}