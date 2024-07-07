
rule Backdoor_Win32_Mizzmo_A{
	meta:
		description = "Backdoor:Win32/Mizzmo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 5a 5a 4d 33 34 35 4d 30 } //1 IZZM345M0
		$a_01_1 = {2f 73 79 6e 63 61 73 73 65 74 2e 68 74 6d 6c } //1 /syncasset.html
		$a_01_2 = {75 70 64 61 74 65 73 79 6e 63 2e 68 74 6d 6c 3f 69 64 3d 25 73 } //1 updatesync.html?id=%s
		$a_01_3 = {44 4f 57 4e 46 4c 31 } //1 DOWNFL1
		$a_01_4 = {43 4d 44 52 55 4e 31 20 74 61 73 6b 6c 69 73 74 } //1 CMDRUN1 tasklist
		$a_01_5 = {54 65 61 6d 50 72 74 73 4b 65 79 } //1 TeamPrtsKey
		$a_01_6 = {51 55 49 54 42 44 52 00 } //1 啑呉䑂R
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}