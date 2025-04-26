
rule Ransom_Win32_Enestedel_Q_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.Q!rsm,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 f8 e8 ?? 00 00 00 e8 ?? 00 00 00 33 c0 [0-18] 19 c8 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}