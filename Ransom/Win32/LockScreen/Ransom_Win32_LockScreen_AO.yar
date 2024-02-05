
rule Ransom_Win32_LockScreen_AO{
	meta:
		description = "Ransom:Win32/LockScreen.AO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 6c 65 74 65 2e 62 61 74 00 } //01 00 
		$a_01_1 = {0c 77 69 6e 6c 6f 63 6b 69 6d 61 67 65 } //01 00 
		$a_01_2 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 20 e4 ee f1 } //01 00 
		$a_01_3 = {d0 e5 e4 e0 ea f2 ee f0 20 f0 e5 e5 f1 f2 f0 e0 } //00 00 
	condition:
		any of ($a_*)
 
}