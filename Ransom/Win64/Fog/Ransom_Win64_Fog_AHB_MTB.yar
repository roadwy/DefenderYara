
rule Ransom_Win64_Fog_AHB_MTB{
	meta:
		description = "Ransom:Win64/Fog.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {65 48 8b 04 25 60 00 00 00 48 89 44 24 08 48 8b 44 24 08 0f b6 40 02 85 c0 74 ?? c7 04 24 01 00 00 00 eb ?? c7 04 24 } //2
		$a_80_1 = {5c 52 41 4e 53 4f 4d 4e 4f 54 45 2e 74 78 74 } //\RANSOMNOTE.txt  1
		$a_80_2 = {4f 42 53 49 44 49 41 4e 4d 49 52 52 4f 52 20 2d 20 50 53 59 4f 50 53 2f 50 53 59 57 41 52 } //OBSIDIANMIRROR - PSYOPS/PSYWAR  1
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}