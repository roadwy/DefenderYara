
rule Trojan_Linux_Pancar_A_MTB{
	meta:
		description = "Trojan:Linux/Pancar.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 63 65 6e 74 72 65 6f 6e 2f 77 77 77 2f 69 6e 63 6c 75 64 65 2f 74 6f 6f 6c 73 2f 63 68 65 63 6b 2e 73 68 } //1 /centreon/www/include/tools/check.sh
		$a_01_1 = {31 db 48 c1 fd 03 48 83 ec 08 e8 35 fe ff ff 48 85 ed 74 1e 0f 1f 84 00 00 00 00 00 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea 48 83 c4 08 5b 5d 41 5c 41 5d 41 5e 41 5f } //1
		$a_01_2 = {48 83 3d c8 08 20 00 00 74 1e b8 00 00 00 00 48 85 c0 74 14 55 bf 20 0e 60 00 48 89 e5 ff d0 5d e9 7b ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}