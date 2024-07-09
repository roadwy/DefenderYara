
rule Ransom_Win32_StopCrypt_SD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8d 14 06 c1 e1 ?? 03 4d ?? c1 e8 ?? 03 45 ?? 33 ca 33 c1 89 4d ?? 89 45 ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}