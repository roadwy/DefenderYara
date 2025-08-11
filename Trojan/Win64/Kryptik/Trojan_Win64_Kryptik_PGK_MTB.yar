
rule Trojan_Win64_Kryptik_PGK_MTB{
	meta:
		description = "Trojan:Win64/Kryptik.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 0a 08 32 35 1f 0a 08 30 05 38 62 05 00 00 1e 08 32 0e 1e 08 30 05 38 f2 04 00 00 38 86 03 00 00 1f 09 08 32 0f 1f 09 08 30 05 38 09 05 00 00 38 72 03 00 00 38 6d 03 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}