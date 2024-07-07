
rule Ransom_Win32_Enestedel_X_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.X!rsm,SIGNATURE_TYPE_PEHSTR_EXT,36 01 36 01 05 00 00 "
		
	strings :
		$a_03_0 = {3c 00 40 00 8b 90 01 01 80 00 40 00 90 00 } //100
		$a_01_1 = {02 00 40 00 8b } //100
		$a_01_2 = {6a 50 6a 03 } //100 偪ͪ
		$a_03_3 = {6a 50 6a 40 ff 15 90 01 02 00 10 90 00 } //10
		$a_03_4 = {6a 1e 6a 40 ff 15 90 01 02 00 10 90 00 } //10
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=310
 
}