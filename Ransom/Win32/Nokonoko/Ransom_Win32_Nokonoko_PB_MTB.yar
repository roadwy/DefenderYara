
rule Ransom_Win32_Nokonoko_PB_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 50 01 8d 40 ?? 0f b6 48 ?? c1 e2 08 03 d1 0f b6 48 ?? c1 e2 08 03 d1 0f b6 48 fa c1 e2 08 03 ca 89 4c 3d c0 89 4c 3d 80 83 c7 04 83 ff } //1
		$a_03_1 = {8b fe 83 e7 3f 90 13 8a 44 3d ?? 30 04 1e 46 3b 75 14 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}