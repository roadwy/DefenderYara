
rule Ransom_Win32_StopCrypt_SLK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 ?? 03 4d ?? 8b d6 c1 e2 ?? 03 55 ?? 03 c6 33 ca 33 c8 89 45 ?? 89 4d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 ?? 8b 45 ?? c1 e0 ?? 03 c3 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}