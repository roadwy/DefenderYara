
rule Ransom_Win32_ContiCrypt_PL_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 90 01 01 ac 90 00 } //01 00 
		$a_03_1 = {aa 4a 0f 85 90 02 04 8b ec 5d c2 0c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}