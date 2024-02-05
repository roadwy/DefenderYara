
rule Ransom_Win32_ContiCrypt_AA_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 04 08 30 04 1f 8b 45 90 01 01 2b c6 48 23 c2 8b d1 8a 04 10 30 04 1f eb 90 0a 30 00 8d 46 90 01 01 23 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}