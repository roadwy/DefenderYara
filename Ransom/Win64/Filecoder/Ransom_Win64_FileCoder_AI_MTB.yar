
rule Ransom_Win64_FileCoder_AI_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c2 49 0f af d1 48 c1 ea 90 01 01 8d 0c 52 89 c2 c1 e1 90 01 01 29 ca 48 63 d2 41 0f b6 14 13 41 32 14 02 41 88 14 00 48 83 c0 01 48 3d 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}