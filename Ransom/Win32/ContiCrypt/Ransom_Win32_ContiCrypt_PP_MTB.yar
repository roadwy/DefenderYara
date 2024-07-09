
rule Ransom_Win32_ContiCrypt_PP_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 03 8d 04 ?? c1 e0 02 2b f0 0f b6 44 ?? ?? 30 [0-04] 8d 04 ?? 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}