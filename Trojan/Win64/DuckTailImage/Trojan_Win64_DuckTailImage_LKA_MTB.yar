
rule Trojan_Win64_DuckTailImage_LKA_MTB{
	meta:
		description = "Trojan:Win64/DuckTailImage.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 15 e0 eb 30 00 4c 0f b6 c1 4c 8d 0d 41 ec 30 00 4c 8b d0 49 83 e2 0f 4f 0f b6 0c 11 46 88 0c 02 48 c1 e8 04 80 e9 01 48 85 c0 75 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}