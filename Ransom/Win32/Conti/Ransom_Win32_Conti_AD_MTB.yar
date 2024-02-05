
rule Ransom_Win32_Conti_AD_MTB{
	meta:
		description = "Ransom:Win32/Conti.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 39 00 75 90 01 01 53 56 57 bf 90 01 01 00 00 00 8d 71 01 8d 5f 90 01 01 8a 06 8d 76 01 0f b6 c0 83 e8 90 00 } //01 00 
		$a_03_1 = {99 f7 fb 8d 42 90 01 01 99 f7 fb 88 56 ff 83 ef 01 75 90 01 01 5f 5e 5b 8d 41 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}