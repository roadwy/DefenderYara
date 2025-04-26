
rule TrojanClicker_Win32_Lochob_A{
	meta:
		description = "TrojanClicker:Win32/Lochob.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 75 fc cc f1 b3 a0 } //2
		$a_01_1 = {63 6f 6f 6e 5f 61 64 76 69 73 65 } //1 coon_advise
		$a_01_2 = {72 5f 62 68 6f 5f 6d 74 78 } //1 r_bho_mtx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}