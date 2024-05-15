
rule Ransom_Win64_Mallox_MKB_MTB{
	meta:
		description = "Ransom:Win64/Mallox.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 98 41 8b 4c 83 fc 8b c1 c1 e8 1e 33 c1 69 c0 65 89 07 6c 03 d0 49 63 c0 41 89 14 83 } //00 00 
	condition:
		any of ($a_*)
 
}