
rule Trojan_Win64_BazarLoader_AL_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 2b 23 08 c9 7e 29 3d 9a e9 f7 e2 7e 67 3d 7d 51 dc 06 0f ?? ?? ?? ?? ?? 3d af 4e d6 0d 0f ?? ?? ?? ?? ?? 3d 9b e9 f7 e2 75 d5 } //10
		$a_00_1 = {8d 50 ff 0f af d0 b8 ff ff ff ff 31 c2 83 ca fe 39 c2 0f 94 45 07 83 f9 0a 0f 9c 45 06 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}