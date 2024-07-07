
rule Trojan_Win64_Icedidcrypt_GH_MTB{
	meta:
		description = "Trojan:Win64/Icedidcrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 03 0f b6 8d 90 01 04 41 88 01 c7 85 90 01 08 8b 85 90 01 04 8b 85 90 01 04 25 03 00 00 80 41 3b c5 8b 85 90 01 04 74 90 01 01 25 03 00 00 80 83 f8 02 8b 85 90 01 04 75 90 00 } //10
		$a_02_1 = {25 03 00 00 80 83 f8 03 75 90 01 01 8b 85 90 01 04 2b c8 8b 85 90 01 04 0f af c1 89 85 90 01 04 4d 03 cd 0f b6 8d 90 01 04 c7 85 90 01 08 8b 85 90 01 04 8b 85 90 01 04 25 03 00 00 80 41 3b c5 8b 85 90 01 04 0f 84 90 00 } //10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=30
 
}