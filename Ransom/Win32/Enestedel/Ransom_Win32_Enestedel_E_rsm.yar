
rule Ransom_Win32_Enestedel_E_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.E!rsm,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 08 00 00 1e 00 "
		
	strings :
		$a_03_0 = {0f bf c9 83 c1 90 01 01 89 85 90 01 02 ff ff 8b c2 99 f7 f9 8b 90 09 07 00 0f b7 0d 90 00 } //1e 00 
		$a_03_1 = {00 10 99 f7 f9 0f bf 90 09 07 00 00 10 0f bf 0d 90 09 0c 00 0f bf 05 90 00 } //0a 00 
		$a_03_2 = {00 10 0f be 0d 90 09 05 00 0f be 05 90 00 } //0a 00 
		$a_03_3 = {00 10 0f bf 0d 90 09 05 00 0f bf 05 90 00 } //05 00 
		$a_03_4 = {00 10 0f bf c0 90 09 05 00 0f b7 05 90 00 } //05 00 
		$a_03_5 = {00 10 0f be d2 90 09 05 00 0f b6 15 90 00 } //05 00 
		$a_03_6 = {00 10 0f be c0 90 09 05 00 0f b6 05 90 00 } //05 00 
		$a_03_7 = {00 10 0f be d2 90 09 05 00 0f b7 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}