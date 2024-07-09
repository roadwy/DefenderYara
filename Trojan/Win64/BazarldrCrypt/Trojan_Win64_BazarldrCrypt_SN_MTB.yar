
rule Trojan_Win64_BazarldrCrypt_SN_MTB{
	meta:
		description = "Trojan:Win64/BazarldrCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d3 f7 d3 44 21 cb 83 e2 05 09 da 44 31 ca 29 c2 f6 d2 48 8b 06 48 8b 5c ?? ?? 88 14 18 bb ?? ?? ?? ?? 48 8b 7c ?? ?? e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}