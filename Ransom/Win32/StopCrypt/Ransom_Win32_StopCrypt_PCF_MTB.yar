
rule Ransom_Win32_StopCrypt_PCF_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 55 ?? c1 e0 04 03 45 ?? 89 4d ?? 33 d0 33 d1 89 55 ?? 8b 45 [0-10] 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 04 03 45 ?? 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}