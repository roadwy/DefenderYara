
rule Ransom_Win32_StopCrypt_PCA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 [0-0a] 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 81 45 ?? 47 86 c8 61 33 c1 2b f0 ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}