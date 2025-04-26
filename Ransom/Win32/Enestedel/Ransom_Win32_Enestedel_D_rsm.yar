
rule Ransom_Win32_Enestedel_D_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.D!rsm,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_03_0 = {01 40 99 f7 fe a2 90 09 08 00 0f be f0 0f be 05 } //40
		$a_03_1 = {01 40 8b ca 99 f7 f9 89 90 09 07 00 01 40 0f be 15 90 09 0c 00 0f bf 05 } //30
		$a_03_2 = {01 40 0f be 15 90 09 05 00 0f be 05 } //10
		$a_03_3 = {01 40 0f be 0d 90 09 05 00 0f be 15 } //10
		$a_03_4 = {01 40 0f bf 15 90 09 05 00 0f be 05 } //10
		$a_03_5 = {01 40 0f bf 15 90 09 05 00 0f bf 05 } //10
	condition:
		((#a_03_0  & 1)*40+(#a_03_1  & 1)*30+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=50
 
}