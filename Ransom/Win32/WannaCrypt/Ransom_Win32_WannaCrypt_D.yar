
rule Ransom_Win32_WannaCrypt_D{
	meta:
		description = "Ransom:Win32/WannaCrypt.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 35 56 6a 01 85 ff 68 0c 03 00 00 74 0d 8b 44 24 18 50 ff 15 90 01 04 eb 0b 90 00 } //01 00 
		$a_01_1 = {6d 5f 25 73 2e 77 6e 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}