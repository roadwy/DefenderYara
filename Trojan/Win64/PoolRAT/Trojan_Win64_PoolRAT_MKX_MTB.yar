
rule Trojan_Win64_PoolRAT_MKX_MTB{
	meta:
		description = "Trojan:Win64/PoolRAT.MKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b f9 0f 1f 84 00 ?? ?? ?? ?? 48 8d 4c 24 20 e8 ?? ?? ?? ?? 30 03 48 8d 5b 01 48 83 ef 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}