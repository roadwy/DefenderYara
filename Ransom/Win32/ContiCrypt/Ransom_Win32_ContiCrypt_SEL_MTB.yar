
rule Ransom_Win32_ContiCrypt_SEL_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.SEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 03 34 9c 88 07 } //1
		$a_01_1 = {b2 2f 32 ca 90 8a 06 90 32 c2 88 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}