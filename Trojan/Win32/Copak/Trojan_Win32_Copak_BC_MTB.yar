
rule Trojan_Win32_Copak_BC_MTB{
	meta:
		description = "Trojan:Win32/Copak.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {01 db 31 02 43 42 43 39 ca 75 eb } //03 00 
		$a_01_1 = {31 1e ba d3 1e e8 9e ba c1 1f 6c a1 46 89 ff 39 c6 75 e3 } //03 00 
		$a_01_2 = {01 d7 31 03 29 d2 43 21 fa 21 d7 39 cb 75 e2 } //02 00 
		$a_01_3 = {43 42 81 c6 34 1e ff 1d 29 f6 81 fb 4c e4 00 01 75 b6 } //02 00 
		$a_01_4 = {47 81 e9 8a b0 76 2a 52 5a 81 ff f4 a4 00 01 75 bf } //02 00 
		$a_01_5 = {29 df 40 81 c7 95 e4 43 f7 81 f8 bd 28 00 01 75 c0 } //00 00 
	condition:
		any of ($a_*)
 
}