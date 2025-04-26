
rule Ransom_Win32_ContiCrypt_RES_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.RES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 03 90 34 a8 88 07 90 43 47 49 83 f9 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}