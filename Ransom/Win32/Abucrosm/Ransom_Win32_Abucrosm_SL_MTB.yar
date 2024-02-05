
rule Ransom_Win32_Abucrosm_SL_MTB{
	meta:
		description = "Ransom:Win32/Abucrosm.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 89 18 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 01 01 6a 90 01 01 e8 90 01 04 8b 5d 90 01 01 2b d8 6a 90 01 01 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 83 45 90 01 02 83 45 90 01 02 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}