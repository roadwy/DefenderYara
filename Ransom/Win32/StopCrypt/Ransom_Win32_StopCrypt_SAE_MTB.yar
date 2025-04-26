
rule Ransom_Win32_StopCrypt_SAE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b d8 89 45 ?? 8b c3 c1 e0 ?? 89 5d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}