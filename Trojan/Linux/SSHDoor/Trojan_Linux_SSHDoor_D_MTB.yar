
rule Trojan_Linux_SSHDoor_D_MTB{
	meta:
		description = "Trojan:Linux/SSHDoor.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 18 89 f1 31 d2 ?? ?? ?? ?? ?? 64 48 8b 04 25 28 00 00 00 48 89 44 24 08 31 c0 e8 2e fc ff ff 89 c2 b8 ff ff ff ff 85 d2 0f 45 44 24 04 48 8b 54 24 08 64 48 33 14 25 28 00 00 00 75 ?? 48 83 c4 18 } //1
		$a_03_1 = {41 80 3c 24 58 0f 85 ?? ?? ?? ?? 0f 1f 44 00 00 e8 0b eb ff ff 0f b7 c8 b8 4f ec c4 4e f7 e1 b8 34 00 00 00 c1 ea 04 0f af d0 29 d1 89 ca ?? ?? ?? ?? ?? ?? 83 fa 19 0f 4f c1 41 88 04 24 49 83 ec 01 4c 39 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}