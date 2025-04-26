
rule Ransom_Win32_ContiCrypt_PH_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8b 44 8c ?? 33 c6 89 44 8c ?? 41 83 f9 ?? 72 ?? 8d 44 24 ?? 50 53 53 ff } //1
		$a_03_1 = {8b cb 8b 44 8c ?? 35 a5 43 07 6f 89 44 8c ?? 41 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}