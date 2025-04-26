
rule Trojan_Win64_Shelma_DAS_MTB{
	meta:
		description = "Trojan:Win64/Shelma.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 39 d0 74 13 48 89 c1 83 e1 1f 8a 4c 0c ?? 41 30 0c 00 48 ff c0 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}