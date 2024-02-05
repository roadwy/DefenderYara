
rule Ransom_Win32_Kasacrypt_A{
	meta:
		description = "Ransom:Win32/Kasacrypt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6b 6f 72 72 65 6b 74 6f 72 } //02 00 
		$a_01_1 = {6b 6f 72 72 65 6b 74 6f 72 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //02 00 
		$a_01_2 = {63 3a 5c 6c 6f 6f 6b 2e 6a 70 67 } //00 00 
		$a_01_3 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}