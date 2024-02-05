
rule Ransom_Win32_Enestedel_Q_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.Q!rsm,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 f8 e8 90 01 01 00 00 00 e8 90 01 01 00 00 00 33 c0 90 02 18 19 c8 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}