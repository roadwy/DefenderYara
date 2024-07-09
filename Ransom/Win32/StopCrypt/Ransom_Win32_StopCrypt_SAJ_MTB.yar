
rule Ransom_Win32_StopCrypt_SAJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 de 33 d8 31 5d ?? 2b 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}