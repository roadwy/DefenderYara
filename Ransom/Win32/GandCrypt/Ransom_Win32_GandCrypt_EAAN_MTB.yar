
rule Ransom_Win32_GandCrypt_EAAN_MTB{
	meta:
		description = "Ransom:Win32/GandCrypt.EAAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 94 06 32 09 00 00 88 14 08 8b 7c 24 10 40 3b c7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}