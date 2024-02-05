
rule Ransom_Win32_Nemty_D{
	meta:
		description = "Ransom:Win32/Nemty.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4e 45 4d 54 59 } //02 00 
		$a_01_1 = {44 45 43 52 59 50 54 2e 74 78 74 } //02 00 
		$a_01_2 = {66 75 63 6b 61 76 } //02 00 
		$a_01_3 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //02 00 
		$a_01_4 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}