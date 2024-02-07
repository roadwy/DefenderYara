
rule Ransom_Win32_Filecoder_BE_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //03 00  vssadmin delete shadows /all
		$a_81_1 = {59 6f 75 72 20 41 6c 6c 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 20 57 69 74 68 20 48 69 67 68 20 6c 65 76 65 6c 20 43 72 79 70 74 6f 67 72 61 70 68 79 20 41 6c 67 6f 72 69 74 68 6d } //01 00  Your All Files Encrypted With High level Cryptography Algorithm
		$a_81_2 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //01 00  @protonmail.com
		$a_81_3 = {52 65 61 64 2d 4d 65 2d 4e 6f 77 2e 74 78 74 } //01 00  Read-Me-Now.txt
		$a_81_4 = {49 66 20 59 6f 75 20 4e 65 65 64 20 59 6f 75 72 20 46 69 6c 65 73 20 59 6f 75 20 53 68 6f 75 6c 64 20 50 61 79 20 46 6f 72 20 44 65 63 72 79 70 74 69 6f 6e } //00 00  If You Need Your Files You Should Pay For Decryption
	condition:
		any of ($a_*)
 
}