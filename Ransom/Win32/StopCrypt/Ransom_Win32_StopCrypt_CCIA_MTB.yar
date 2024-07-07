
rule Ransom_Win32_StopCrypt_CCIA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CCIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 14 8b 4c 24 10 30 04 0a 83 bc 24 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}