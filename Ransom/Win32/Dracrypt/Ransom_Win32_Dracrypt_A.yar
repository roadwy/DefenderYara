
rule Ransom_Win32_Dracrypt_A{
	meta:
		description = "Ransom:Win32/Dracrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {2e 00 64 00 65 00 73 00 75 00 63 00 72 00 70 00 74 00 } //02 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 64 65 6c 74 61 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 64 65 73 75 43 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 64 65 73 75 43 72 79 70 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}