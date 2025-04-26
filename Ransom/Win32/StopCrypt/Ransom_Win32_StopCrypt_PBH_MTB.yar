
rule Ransom_Win32_StopCrypt_PBH_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 [0-06] c1 e1 04 03 4d ?? 50 03 f3 8d 45 ?? 33 ce 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 4d ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_StopCrypt_PBH_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 ?? c1 e1 04 03 4d ?? 50 03 d6 8d 45 ?? 33 ca 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 4d ?? e8 } //1
		$a_03_1 = {c1 e8 05 03 45 [0-06] c1 e1 04 03 4d ?? 50 03 d3 8d 45 ?? 33 ca 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 4d ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}