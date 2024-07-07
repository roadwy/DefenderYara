
rule Ransom_Win32_StopCrypt_UTY_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.UTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f9 8b d7 c1 e2 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b c7 c1 e8 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8d 0c 3b 31 4c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 3d 90 01 08 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}