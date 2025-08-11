
rule Ransom_Win64_Basta_VZT_MTB{
	meta:
		description = "Ransom:Win64/Basta.VZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 03 d7 0f b7 ff 66 33 d1 0f b7 c2 0f af f8 b8 bf 00 00 00 ff 08 48 8b 44 24 28 44 0f b6 08 0f b6 84 24 ?? ?? ?? ?? 44 0f af c8 b8 0d 37 76 51 41 f7 e1 b8 bf 00 00 00 c1 ea 09 44 69 c2 49 06 00 00 48 8b 15 ?? ?? ?? ?? 45 2b c8 4c 63 00 46 23 0c 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}