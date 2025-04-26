
rule Ransom_Win32_StopCrypt_YAL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.YAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 18 e8 6b ff ff ff 8b 44 24 18 83 c0 ?? 89 44 24 10 83 6c 24 10 64 8a 4c 24 10 8b 44 24 14 30 0c 30 83 bc 24 5c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}