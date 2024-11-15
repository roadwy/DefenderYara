
rule Ransom_Linux_Fog_A_MTB{
	meta:
		description = "Ransom:Linux/Fog.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 d0 48 89 6c 24 d8 4c 89 64 24 e0 4c 89 6c 24 e8 41 89 f4 4c 89 74 24 f0 4c 89 7c 24 f8 48 81 ec 28 01 00 00 ?? ?? ?? ?? ?? 89 fe 41 89 fd 49 89 d7 41 89 ce 4c 89 44 24 08 48 89 ef 44 89 4c 24 04 } //1
		$a_01_1 = {48 8b 57 08 ff c1 89 d0 48 c1 ea 20 88 47 08 88 57 0c c1 e8 08 c1 ea 08 88 47 09 c1 e8 08 88 57 0d c1 ea 08 88 47 0a 88 57 0e c1 e8 08 c1 ea 08 88 47 0b 88 57 0f 48 83 c7 08 83 f9 19 } //1
		$a_01_2 = {2e 66 6f 67 } //1 .fog
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}