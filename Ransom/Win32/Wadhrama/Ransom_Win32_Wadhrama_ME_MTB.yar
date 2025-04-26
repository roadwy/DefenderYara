
rule Ransom_Win32_Wadhrama_ME_MTB{
	meta:
		description = "Ransom:Win32/Wadhrama.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 0f af 45 ?? 03 c6 8b 4d ?? 8d 04 c1 89 45 ?? 8a 45 ?? 32 c3 88 45 ?? 66 83 7d ?? 00 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}