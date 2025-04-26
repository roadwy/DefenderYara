
rule Ransom_Win32_Snatch_MK_MTB{
	meta:
		description = "Ransom:Win32/Snatch.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_1 = {2a 2e 62 61 6b 2a 2e 63 73 76 2a 2e 64 61 74 2a 2e 64 62 66 2a 2e 6a 70 67 2a 2e 70 6e 67 2a 2e 72 61 72 2a 2e 73 71 6c 2a 2e 74 78 74 2a 2e 78 6c 73 2a 2e 7a 69 70 } //1 *.bak*.csv*.dat*.dbf*.jpg*.png*.rar*.sql*.txt*.xls*.zip
		$a_81_2 = {68 69 6a 61 63 6b 65 64 } //1 hijacked
		$a_81_3 = {44 65 63 72 79 70 74 2e 74 78 74 } //1 Decrypt.txt
		$a_81_4 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 3a } //1 Encrypted files:
		$a_81_5 = {50 65 72 73 6f 6e 61 6c 20 4b 65 79 3a } //1 Personal Key:
		$a_81_6 = {44 45 4b 2d 49 6e 66 6f 44 4e 53 } //1 DEK-InfoDNS
		$a_81_7 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Ransom_Win32_Snatch_MK_MTB_2{
	meta:
		description = "Ransom:Win32/Snatch.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 45 48 45 4e 4e 41 2d 4b 45 59 2d 52 45 41 44 4d 45 2e 74 78 74 } //1 GEHENNA-KEY-README.txt
		$a_81_1 = {47 45 48 45 4e 4e 41 2d 52 45 41 44 4d 45 2d 57 41 52 4e 49 4e 47 2e 68 74 6d 6c } //1 GEHENNA-README-WARNING.html
		$a_81_2 = {49 54 20 49 53 20 49 4d 50 4f 53 53 49 42 4c 45 20 54 4f 20 47 45 54 20 59 4f 55 52 20 46 49 4c 45 53 20 42 41 43 4b 20 57 49 54 48 4f 55 54 20 4f 55 52 20 53 50 45 43 49 41 4c 20 44 45 43 52 59 50 54 49 4f 4e 20 54 4f 4f 4c } //1 IT IS IMPOSSIBLE TO GET YOUR FILES BACK WITHOUT OUR SPECIAL DECRYPTION TOOL
		$a_81_3 = {2d 2d 2d 2d 2d 45 4e 44 } //1 -----END
		$a_81_4 = {2d 2d 2d 2d 2d 42 45 47 49 4e } //1 -----BEGIN
		$a_81_5 = {47 2d 45 2d 48 2d 45 2d 4e 2d 4e 2d 41 } //1 G-E-H-E-N-N-A
		$a_81_6 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=4
 
}