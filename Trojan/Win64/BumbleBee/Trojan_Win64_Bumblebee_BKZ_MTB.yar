
rule Trojan_Win64_Bumblebee_BKZ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.BKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 09 41 0f b6 44 09 ?? 00 41 01 44 0f b6 41 01 41 0f b6 54 09 02 41 0f b6 44 08 02 41 88 44 09 ?? 41 88 54 08 ?? 0f b6 01 0f b6 51 01 0f b6 54 0a 02 02 54 08 ?? 0f b6 c2 0f b6 54 08 02 43 32 54 13 ff 41 88 52 ff 48 83 eb 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}