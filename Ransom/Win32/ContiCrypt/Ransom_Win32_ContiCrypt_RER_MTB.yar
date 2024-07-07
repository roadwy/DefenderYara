
rule Ransom_Win32_ContiCrypt_RER_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.RER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 90 47 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}