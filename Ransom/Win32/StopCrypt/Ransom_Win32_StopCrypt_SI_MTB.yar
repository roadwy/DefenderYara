
rule Ransom_Win32_StopCrypt_SI_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 37 c1 ee ?? 03 75 ?? 03 c3 33 c1 33 f0 89 4d ?? 89 45 ?? 89 75 ?? 8b 45 ?? 01 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}