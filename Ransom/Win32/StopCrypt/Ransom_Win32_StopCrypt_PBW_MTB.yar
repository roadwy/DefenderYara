
rule Ransom_Win32_StopCrypt_PBW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 31 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 2b 75 ?? 83 0d [0-08] 8b c6 c1 e8 05 03 45 ?? 8b ce c1 e1 04 03 4d ?? 50 89 45 ?? 8d 14 33 8d 45 ?? 33 ca 50 c7 05 [0-0a] 89 4d ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}