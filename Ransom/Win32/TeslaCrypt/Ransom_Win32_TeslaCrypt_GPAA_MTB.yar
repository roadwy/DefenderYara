
rule Ransom_Win32_TeslaCrypt_GPAA_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 8c 24 ?? ?? ?? ?? 89 44 24 ?? 66 8b 54 24 ?? 66 81 f2 ?? ?? 66 89 94 24 ?? ?? ?? ?? 66 81 f9 ?? ?? 77 ad } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}