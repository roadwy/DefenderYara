
rule Ransom_Win32_HiddenTear_SA{
	meta:
		description = "Ransom:Win32/HiddenTear.SA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 52 75 73 68 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 have been encrypted with Rush Ransomware
		$a_01_1 = {5c 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 59 00 4f 00 55 00 52 00 5f 00 46 00 49 00 4c 00 45 00 53 00 2e 00 48 00 54 00 4d 00 4c 00 } //1 \DECRYPT_YOUR_FILES.HTML
		$a_01_2 = {5c 53 61 6e 63 74 69 6f 6e 20 52 61 6e 73 6f 6d 77 61 72 65 5c 50 72 6f 6a 65 63 74 20 45 6e 63 72 79 70 74 6f 72 5c 68 69 64 64 65 6e 2d 74 65 61 72 } //1 \Sanction Ransomware\Project Encryptor\hidden-tear
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}