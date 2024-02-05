
rule Ransom_Win32_Clop_MR_MTB{
	meta:
		description = "Ransom:Win32/Clop.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 14 81 e9 90 0a 46 00 33 85 90 01 04 89 85 90 02 14 c1 85 90 02 08 8b 95 90 01 04 33 95 90 01 04 89 95 90 01 04 8b 45 90 01 01 8b 4d 90 01 01 8b 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}