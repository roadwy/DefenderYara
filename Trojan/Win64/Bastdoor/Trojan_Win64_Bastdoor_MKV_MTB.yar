
rule Trojan_Win64_Bastdoor_MKV_MTB{
	meta:
		description = "Trojan:Win64/Bastdoor.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 31 ed 48 83 e1 03 74 ?? 66 0f 1f 84 00 00 00 00 00 42 0f b6 54 2c ?? 43 30 14 2c 49 ff c5 4c 39 e9 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}