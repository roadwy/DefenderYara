
rule Ransom_Win32_ContiCrypt_CEDD_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.CEDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 4d 08 89 4d f8 8b c5 } //1
		$a_01_1 = {bb 32 00 00 00 33 5d 18 83 c3 3a 89 5d 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}