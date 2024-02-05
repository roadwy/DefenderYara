
rule Ransom_Win32_ContiCrypt_OR_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 88 07 90 46 47 } //01 00 
		$a_01_1 = {8a 03 34 95 88 07 43 47 } //01 00 
		$a_01_2 = {8a 07 90 32 c2 0f b6 4f 01 90 32 ca 3c 01 90 } //00 00 
	condition:
		any of ($a_*)
 
}