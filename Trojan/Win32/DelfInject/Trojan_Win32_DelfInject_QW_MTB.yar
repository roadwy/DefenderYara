
rule Trojan_Win32_DelfInject_QW_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_00_0 = {42 00 42 00 41 00 42 00 4f 00 52 00 54 00 05 00 42 00 42 00 41 00 4c 00 4c } //03 00 
		$a_00_1 = {54 00 46 00 52 00 4d 00 5f 00 4c 00 49 00 4e 00 5f 00 53 00 59 00 53 00 54 00 45 00 4d } //03 00 
		$a_81_2 = {63 72 79 70 74 33 32 } //03 00  crypt32
		$a_81_3 = {42 69 74 6d 61 70 2e 44 61 74 61 } //03 00  Bitmap.Data
		$a_81_4 = {62 74 6e 5f 63 72 65 65 72 5f 73 79 73 74 65 6d 65 43 6c 69 63 6b } //03 00  btn_creer_systemeClick
		$a_81_5 = {41 50 72 6f 70 6f 73 32 43 6c 69 63 6b } //03 00  APropos2Click
		$a_81_6 = {76 76 76 6a 6a 6a 63 63 63 61 61 61 61 61 61 62 62 62 62 62 62 61 61 61 61 61 61 65 65 65 6e 6e 6e } //00 00  vvvjjjcccaaaaaabbbbbbaaaaaaeeennn
	condition:
		any of ($a_*)
 
}