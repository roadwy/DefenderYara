
rule Trojan_Linux_SAgnt_G_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 8b 84 24 a8 08 00 00 48 83 c0 01 0f b6 00 3c 45 0f 85 b8 00 00 00 48 8b 84 24 a8 08 00 00 48 83 c0 02 0f b6 00 3c 4c 0f 85 a1 00 00 00 48 8b 84 24 a8 08 00 00 48 83 c0 03 0f b6 00 3c 46 } //1
		$a_00_1 = {4c 8b 4c 24 10 48 8b 3d e0 1f 1d 00 31 c0 4c 8d 05 f8 cc 15 00 48 8d 0d ab cd 15 00 48 8d 15 06 cd 15 00 be 01 00 00 00 e8 f7 3e ff ff 48 8b 7c 24 10 48 39 df } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}