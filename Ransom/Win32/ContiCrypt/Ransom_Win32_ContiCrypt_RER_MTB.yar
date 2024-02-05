
rule Ransom_Win32_ContiCrypt_RER_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.RER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 90 47 49 } //00 00 
	condition:
		any of ($a_*)
 
}