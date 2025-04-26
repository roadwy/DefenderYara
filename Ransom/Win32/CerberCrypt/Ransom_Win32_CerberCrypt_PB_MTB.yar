
rule Ransom_Win32_CerberCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/CerberCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 01 8b 55 ?? 81 c2 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 33 10 8b 4d ?? 03 4d ?? 89 11 eb ?? 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}