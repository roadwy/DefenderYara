
rule Ransom_Win32_Abucrosm_A_MTB{
	meta:
		description = "Ransom:Win32/Abucrosm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 2b d1 83 c2 c3 8d 4a 28 02 c9 02 c1 8b 37 89 1d ?? ?? ?? ?? 81 c6 50 96 07 01 8a da 2a 5c 24 18 80 eb 1c 0f b6 cb 3b 4c 24 0c 72 17 0f b6 c8 66 01 0d ?? ?? ?? ?? 8b 4c 24 0c 8a d9 2a d8 80 eb 3d eb 04 8b 4c 24 0c 8a c3 89 37 2a c2 83 c7 04 2a c4 2c 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}