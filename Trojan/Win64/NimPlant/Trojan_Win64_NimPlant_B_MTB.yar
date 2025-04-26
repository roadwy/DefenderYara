
rule Trojan_Win64_NimPlant_B_MTB{
	meta:
		description = "Trojan:Win64/NimPlant.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 0a 48 83 c2 01 41 31 c1 c1 e8 08 45 0f b6 c9 43 33 04 88 48 39 ca 75 e5 5b 5e } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}