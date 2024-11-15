
rule Trojan_Win64_CryptInject_ZAS_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 f1 66 41 89 44 11 ?? 48 89 e8 48 83 c7 08 4d 89 cc 49 83 01 01 48 d3 f8 4c 89 c3 83 e0 ee 41 30 45 00 48 8d 05 ?? ?? ?? ?? 48 39 c7 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}