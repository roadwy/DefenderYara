
rule Ransom_Win32_Abucrosm_AD_MTB{
	meta:
		description = "Ransom:Win32/Abucrosm.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 ce 83 e6 03 75 0d 89 fb 66 01 da 6b d2 03 c1 ca 04 89 d7 30 10 40 e2 e7 } //00 00 
	condition:
		any of ($a_*)
 
}