
rule Ransom_Win32_StopCrypt_CRIS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CRIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}