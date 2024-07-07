
rule Ransom_Win32_StopCrypt_SH_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 3c 01 44 24 90 01 01 8b 54 24 90 01 01 33 54 24 90 01 01 8b 44 24 90 01 01 81 44 24 90 01 05 33 c2 2b f0 83 eb 90 01 01 89 44 24 90 01 01 89 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}