
rule Virus_Win64_Expiro_RR_MTB{
	meta:
		description = "Virus:Win64/Expiro.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ca 41 8b d1 44 33 d1 8b 4c 24 74 45 88 57 fc 45 88 1f 4d 8d 7f 08 41 c1 ca 08 45 88 57 f3 41 c1 cb 08 45 88 5f f7 } //1
		$a_01_1 = {41 70 70 56 43 6c 69 65 6e 74 2e 70 64 62 } //1 AppVClient.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Virus_Win64_Expiro_RR_MTB_2{
	meta:
		description = "Virus:Win64/Expiro.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 45 48 c1 c9 1e 8b f8 c1 ca 1c 0f af 55 08 c1 e7 18 44 89 4d 48 33 d1 44 33 c2 45 33 c4 45 8b e2 45 88 46 fc 41 8b d0 41 88 06 } //1
		$a_01_1 = {41 70 70 56 43 6c 69 65 6e 74 2e 70 64 62 } //1 AppVClient.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}