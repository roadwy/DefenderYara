
rule Trojan_Win64_RedLine_ASJ_MTB{
	meta:
		description = "Trojan:Win64/RedLine.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 0f b6 14 11 41 8a c1 83 e0 0f 0f b6 0c 18 32 ca 43 88 0c 11 4d 85 c9 74 07 41 32 cb 43 88 0c 11 44 0f b6 da 49 83 c1 01 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}