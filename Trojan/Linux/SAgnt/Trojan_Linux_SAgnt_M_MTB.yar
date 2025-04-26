
rule Trojan_Linux_SAgnt_M_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 52 e8 49 0b 00 00 55 53 51 52 48 01 fe 56 48 29 fe 41 80 f8 0e 0f 85 67 0a 00 00 55 48 89 e5 44 8b 09 49 89 d0 48 89 f2 ?? ?? ?? ?? 56 8a 07 ff ca 88 c1 24 07 c0 e9 03 48 c7 c3 00 fd ff ff 48 d3 e3 88 c1 } //2
		$a_01_1 = {48 8b 54 24 e8 44 89 f8 44 29 f0 44 0f b6 2c 02 44 89 f8 41 ff c7 ff cd 44 88 2c 02 0f 95 c2 31 c0 44 3b 7c 24 e4 0f 92 c0 85 c2 75 d3 44 3b 7c 24 e4 0f 82 45 f7 ff ff 41 81 fb ff ff ff 00 77 16 4c 39 e7 b8 01 00 00 00 74 23 eb 07 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}