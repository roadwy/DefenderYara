
rule Ransom_Win32_StopCrypt_CRIS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CRIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}