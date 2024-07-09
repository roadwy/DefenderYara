
rule Ransom_Win32_StopCrypt_ST_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 45 0c 33 f8 89 7d ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 5d ?? ff 4d ?? 89 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}