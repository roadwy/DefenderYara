
rule Ransom_Win32_TeslaCrypt_ARA_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 57 04 02 d1 30 14 30 8b 0d ?? ?? ?? ?? 8a 49 02 0f b6 d1 40 81 c2 ?? ?? ?? ?? 3b c2 76 e1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}