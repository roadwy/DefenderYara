
rule Ransom_Win32_GarrantDecrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/GarrantDecrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 54 00 58 00 54 00 } //1 READ_ME.TXT
		$a_01_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 delete shadows /all /quiet
		$a_00_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your files are encrypted!
		$a_00_3 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 All your important data has been encrypted.
		$a_00_4 = {53 65 6e 64 20 31 20 74 65 73 74 20 69 6d 61 67 65 20 6f 72 20 74 65 78 74 20 66 69 6c 65 20 73 71 75 61 64 68 61 63 6b 40 65 6d 61 69 6c 2e 74 67 } //1 Send 1 test image or text file squadhack@email.tg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}