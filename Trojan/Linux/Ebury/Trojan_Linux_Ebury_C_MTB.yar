
rule Trojan_Linux_Ebury_C_MTB{
	meta:
		description = "Trojan:Linux/Ebury.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 8b 10 48 39 da 74 3e 48 85 d2 75 1a b2 03 48 89 df 89 ed ff 15 e8 85 20 00 48 8d 05 31 c7 20 00 48 89 1c e8 eb 1f ff c5 48 83 c0 08 83 fd 04 75 ce } //1
		$a_00_1 = {49 89 f9 ff c7 41 83 e1 03 46 8a 4c 0c f0 44 32 0a 48 ff c2 44 88 cb 41 83 e1 0f c0 eb 04 44 0f b6 d3 46 8a 94 10 ad 0c 00 00 45 88 10 46 8a 8c 08 ad 0c 00 00 45 88 48 01 49 83 c0 02 39 cf 72 bf } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}