
rule Trojan_Win64_BazarldrCrypt_SN_MTB{
	meta:
		description = "Trojan:Win64/BazarldrCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 d3 f7 d3 44 21 cb 83 e2 05 09 da 44 31 ca 29 c2 f6 d2 48 8b 06 48 8b 5c 90 01 02 88 14 18 bb 90 01 04 48 8b 7c 90 01 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}