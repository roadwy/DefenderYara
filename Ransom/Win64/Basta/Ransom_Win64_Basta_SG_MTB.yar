
rule Ransom_Win64_Basta_SG_MTB{
	meta:
		description = "Ransom:Win64/Basta.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 03 44 8d 47 ?? 48 8d 0c 07 41 0f b6 04 00 30 01 48 8b 03 0f b6 11 41 30 14 00 41 0f b6 0c 00 48 8b 03 30 0c 07 03 3d ?? ?? ?? ?? 3b 3d ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}