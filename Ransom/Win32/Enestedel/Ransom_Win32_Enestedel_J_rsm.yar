
rule Ransom_Win32_Enestedel_J_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.J!rsm,SIGNATURE_TYPE_PEHSTR_EXT,46 00 46 00 07 00 00 "
		
	strings :
		$a_03_0 = {00 10 0f be 0d ?? ?? 00 10 99 81 e9 ?? ?? ?? ?? f7 f9 } //10
		$a_03_1 = {00 10 99 f7 f9 a2 90 09 05 00 0f be 05 } //10
		$a_03_2 = {00 10 0f be 0d 90 09 05 00 0f bf 05 } //10
		$a_03_3 = {00 10 0f bf 0d 90 09 05 00 0f bf 05 } //10
		$a_03_4 = {00 10 0f be 0d 90 09 05 00 0f be 05 } //10
		$a_03_5 = {00 10 0f be 0d 90 09 05 00 0f be 15 } //10
		$a_03_6 = {00 10 0f be 15 90 09 05 00 0f be 0d } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10+(#a_03_6  & 1)*10) >=70
 
}