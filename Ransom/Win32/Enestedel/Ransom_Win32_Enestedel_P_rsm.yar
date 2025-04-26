
rule Ransom_Win32_Enestedel_P_rsm{
	meta:
		description = "Ransom:Win32/Enestedel.P!rsm,SIGNATURE_TYPE_PEHSTR_EXT,36 01 2c 01 06 00 00 "
		
	strings :
		$a_01_0 = {10 15 03 00 } //100
		$a_01_1 = {88 13 00 00 } //100
		$a_03_2 = {6a 50 6a 03 ?? 6a 01 68 00 00 00 80 68 [0-02] 00 10 ff } //100
		$a_03_3 = {00 10 0f be 0d 90 09 05 00 0f bf 05 } //10
		$a_03_4 = {00 10 0f bf 0d 90 09 05 00 0f be 05 } //10
		$a_03_5 = {00 10 0f be 05 90 09 05 00 0f be 0d } //10
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_03_2  & 1)*100+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10) >=300
 
}