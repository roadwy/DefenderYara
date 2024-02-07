
rule Ransom_MSIL_HiddenTear_ST_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 75 73 69 6e 67 20 73 65 63 72 65 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 6d 65 74 68 6f 64 } //01 00  Your files has been encrypted by using secret encryption method
		$a_81_1 = {54 68 65 72 65 20 69 73 20 6e 6f 20 65 61 73 79 20 6d 65 74 68 6f 64 20 64 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 20 75 6e 6c 65 73 73 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 67 75 65 73 73 20 79 6f 75 72 20 6b 65 79 21 } //01 00  There is no easy method decrypting files unless you want to guess your key!
		$a_81_2 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 6b 65 79 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 3a } //01 00  Your personal key for decryption:
		$a_81_3 = {49 66 20 79 6f 75 20 61 72 65 20 73 6d 61 72 74 20 79 6f 75 20 6b 6e 6f 77 20 68 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 20 74 68 69 73 20 6b 65 79 2e } //01 00  If you are smart you know how to decrypt your files with this key.
		$a_81_4 = {4b 65 79 20 69 73 20 77 72 6f 6e 67 21 20 50 6c 65 61 73 65 20 72 65 73 74 61 72 74 20 74 68 65 20 70 72 6f 67 72 61 6d 20 74 6f 20 73 65 6e 64 20 69 74 20 61 67 61 69 6e 2e } //01 00  Key is wrong! Please restart the program to send it again.
		$a_81_5 = {64 65 6c 20 2f 51 20 2f 46 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6b 61 73 70 65 72 } //01 00  del /Q /F C:\Program Files\kasper
		$a_81_6 = {64 65 6c 20 2f 51 20 2f 46 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 6f 72 74 6f 6e } //01 00  del /Q /F C:\Program Files\Norton
		$a_81_7 = {64 65 6c 20 2f 51 20 2f 46 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 63 61 66 65 65 } //01 00  del /Q /F C:\Program Files\Mcafee
		$a_81_8 = {64 65 6c 20 2f 51 20 2f 46 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 74 72 6f 6a 61 6e } //01 00  del /Q /F C:\Program Files\trojan
		$a_81_9 = {64 65 6c 20 2f 51 20 2f 46 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6e 6f 6f 64 33 32 } //01 00  del /Q /F C:\Program Files\nood32
		$a_81_10 = {64 65 6c 20 2f 51 20 2f 46 20 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 70 61 6e 64 61 } //00 00  del /Q /F C:\Program Files\panda
		$a_00_11 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}