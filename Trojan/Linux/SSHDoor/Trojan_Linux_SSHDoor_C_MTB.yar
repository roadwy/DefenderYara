
rule Trojan_Linux_SSHDoor_C_MTB{
	meta:
		description = "Trojan:Linux/SSHDoor.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 57 41 56 49 89 f6 41 55 41 54 55 89 fd 53 48 81 ec 98 09 00 00 48 8b 3e 64 48 8b 04 25 28 00 00 00 48 89 84 24 88 09 00 00 31 c0 c7 44 24 34 01 00 00 00 c7 44 24 60 ff ff ff ff c7 44 24 64 ff ff ff ff e8 37 ae 04 00 8d 7d 01 } //1
		$a_00_1 = {53 31 c9 ba 01 00 00 00 31 f6 48 89 fb 48 83 ec 10 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 e8 0a fc ff ff 31 d2 85 c0 48 0f 45 d3 48 8b 4c 24 08 64 48 33 0c 25 28 00 00 00 75 09 48 83 c4 10 48 89 d0 5b c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}