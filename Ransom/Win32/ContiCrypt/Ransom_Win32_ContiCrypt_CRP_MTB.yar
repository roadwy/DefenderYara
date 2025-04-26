
rule Ransom_Win32_ContiCrypt_CRP_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.CRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 46 47 90 49 90 83 f9 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}