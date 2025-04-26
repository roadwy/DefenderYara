
rule Ransom_Win32_NordCrypter_YAA_MTB{
	meta:
		description = "Ransom:Win32/NordCrypter.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 43 f3 33 d2 f7 75 fc 47 8a 04 32 8b 55 f8 32 04 0a 8b 55 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}