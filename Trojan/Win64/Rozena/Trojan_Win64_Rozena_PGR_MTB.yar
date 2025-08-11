
rule Trojan_Win64_Rozena_PGR_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 98 48 8d 14 85 00 00 00 00 48 8b 45 10 48 01 d0 8b 00 48 63 d0 48 8b 45 18 48 01 d0 8b 55 fc 48 63 ca 48 8b 55 f0 48 01 ca 0f b6 00 88 02 83 45 fc 01 8b 45 fc 3b 45 f8 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}