
rule Ransom_Win32_WannaCrypt_DA_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {6d 73 67 2f 6d 5f 64 61 6e 69 73 68 2e 77 6e 72 79 } //01 00  msg/m_danish.wnry
		$a_81_1 = {6d 73 67 2f 6d 5f 64 75 74 63 68 2e 77 6e 72 79 } //01 00  msg/m_dutch.wnry
		$a_81_2 = {6d 73 67 2f 6d 5f 66 69 6c 69 70 69 6e 6f 2e 77 6e 72 79 } //01 00  msg/m_filipino.wnry
		$a_81_3 = {6d 73 67 2f 6d 5f 66 72 65 6e 63 68 2e 77 6e 72 79 } //01 00  msg/m_french.wnry
		$a_81_4 = {6d 73 67 2f 6d 5f 67 65 72 6d 61 6e 2e 77 6e 72 79 } //00 00  msg/m_german.wnry
	condition:
		any of ($a_*)
 
}