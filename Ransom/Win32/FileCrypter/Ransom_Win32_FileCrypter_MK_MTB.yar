
rule Ransom_Win32_FileCrypter_MK_MTB{
	meta:
		description = "Ransom:Win32/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 65 64 20 62 79 20 42 6c 61 63 6b 52 61 62 62 69 74 } //01 00  Encrypted by BlackRabbit
		$a_81_1 = {7b 45 4e 43 52 59 50 54 45 4e 44 45 44 7d } //01 00  {ENCRYPTENDED}
		$a_81_2 = {7b 45 4e 43 52 59 50 54 53 54 41 52 54 7d } //01 00  {ENCRYPTSTART}
		$a_81_3 = {68 6f 77 5f 74 6f 5f 64 65 63 72 79 70 74 2e 68 74 61 } //01 00  how_to_decrypt.hta
		$a_81_4 = {63 6f 6e 66 69 67 2e 74 78 74 } //01 00  config.txt
		$a_81_5 = {68 74 61 2e 74 78 74 } //01 00  hta.txt
		$a_81_6 = {2f 63 20 22 70 69 6e 67 20 30 2e 30 2e 30 2e 30 26 64 65 6c 20 22 } //01 00  /c "ping 0.0.0.0&del "
		$a_81_7 = {45 4e 44 20 45 4e 43 52 59 50 54 20 4f 4e 4c 59 20 45 58 54 45 4e 41 54 49 4f 4e 53 } //00 00  END ENCRYPT ONLY EXTENATIONS
		$a_00_8 = {78 d3 00 00 12 00 } //12 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_FileCrypter_MK_MTB_2{
	meta:
		description = "Ransom:Win32/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 05 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 41 6e 64 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 6c 69 6d 69 74 65 64 21 } //01 00  Files have been encrypted!And Your computer has been limited!
		$a_81_1 = {52 65 66 65 72 65 6e 63 65 20 4e 75 6d 62 65 72 20 3a 20 43 54 20 2d } //05 00  Reference Number : CT -
		$a_81_2 = {73 65 6e 64 20 24 34 30 20 74 6f 20 6f 75 72 20 62 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 } //01 00  send $40 to our bitcoin wallet
		$a_81_3 = {66 6c 61 67 20 69 6e 20 62 61 73 65 36 34 3a } //05 00  flag in base64:
		$a_81_4 = {54 68 65 72 65 27 73 20 6d 61 6c 77 61 72 65 20 65 76 65 72 79 77 68 65 72 65 } //01 00  There's malware everywhere
		$a_81_5 = {41 74 74 65 6e 74 69 6f 6e 56 69 63 74 69 6d } //00 00  AttentionVictim
		$a_00_6 = {5d 04 00 00 b9 3f 04 80 5c 28 00 00 ba 3f 04 } //80 00 
	condition:
		any of ($a_*)
 
}