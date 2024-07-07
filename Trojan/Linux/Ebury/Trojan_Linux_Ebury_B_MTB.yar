
rule Trojan_Linux_Ebury_B_MTB{
	meta:
		description = "Trojan:Linux/Ebury.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 83 e0 03 ff c0 42 32 4c 04 f0 88 cb 83 e1 0f c0 eb 04 44 0f b6 c3 46 8a 84 02 65 0d 00 00 44 88 06 8a 8c 0a 65 0d 00 00 88 4e 01 48 83 c6 02 41 89 c0 42 8a 0c 07 84 c9 75 c5 c6 06 00 5b c3 } //1
		$a_00_1 = {89 c0 4c 89 ef 48 c1 e0 04 48 8b 74 28 08 e8 30 fd ff ff 48 85 c0 74 0e 41 83 fc 01 75 05 48 89 c3 eb 17 48 89 c3 ff 05 14 bc 20 00 8b 05 0e bc 20 00 3b 05 04 bc 20 00 72 c6 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}