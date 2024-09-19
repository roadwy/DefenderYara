
rule Ransom_Win32_Tescrypt_NB_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 08 83 f8 00 0f 95 c3 8a 7c 24 ?? 30 fb f6 c3 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}