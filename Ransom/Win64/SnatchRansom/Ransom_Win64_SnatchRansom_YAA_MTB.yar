
rule Ransom_Win64_SnatchRansom_YAA_MTB{
	meta:
		description = "Ransom:Win64/SnatchRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 8d 14 92 c1 e2 02 41 29 d1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08 } //2
		$a_03_1 = {41 bb fd 9e 5f 22 41 29 f3 49 83 c3 01 41 ba ?? ?? ?? ?? 41 89 c9 89 c8 41 f7 ea } //3
		$a_03_2 = {41 89 c9 89 c8 41 f7 ea 42 8d 04 0a c1 f8 05 89 cb c1 fb 1f 29 d8 6b c0 3e 41 29 c1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2) >=5
 
}