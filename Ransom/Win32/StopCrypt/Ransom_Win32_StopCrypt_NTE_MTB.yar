
rule Ransom_Win32_StopCrypt_NTE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.NTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 45 f4 83 c0 90 01 01 89 45 f8 83 6d f8 64 8a 4d f8 30 0c 1e 83 ff 0f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}