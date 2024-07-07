
rule DoS_Win32_SonicVote_A_dha{
	meta:
		description = "DoS:Win32/SonicVote.A!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 6f 6e 6c 79 20 74 68 69 6e 67 20 74 68 61 74 20 77 65 20 6c 65 61 72 6e 20 66 72 6f 6d 20 6e 65 77 20 65 6c 65 63 74 69 6f 6e 73 20 69 73 20 77 65 20 6c 65 61 72 6e 65 64 20 6e 6f 74 68 69 6e 67 20 66 72 6f 6d 20 74 68 65 20 6f 6c 64 21 22 3c 2f 62 3e 3c 2f 70 3e } //1 The only thing that we learn from new elections is we learned nothing from the old!"</b></p>
		$a_01_1 = {3c 70 3e 54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 79 6f 75 72 20 76 6f 74 65 21 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 65 73 2c 20 76 69 64 65 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 65 74 63 2e 20 68 61 76 65 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 21 3c 2f 70 3e } //1 <p>Thank you for your vote! All your files, documents, photoes, videos, databases etc. have been successfully encrypted!</p>
		$a_01_2 = {3c 70 3e 4e 6f 77 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 61 20 73 70 65 63 69 61 6c 20 49 44 3a 3c 62 3e 20 3c 2f 62 3e 3c 2f 70 3e } //1 <p>Now your computer has a special ID:<b> </b></p>
		$a_01_3 = {3c 70 3e 44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 64 65 63 72 79 70 74 20 74 68 65 6e 20 62 79 20 79 6f 75 72 73 65 6c 66 20 2d 20 69 74 27 73 20 69 6d 70 6f 73 73 69 62 6c 65 21 } //1 <p>Do not try to decrypt then by yourself - it's impossible!
		$a_01_4 = {3c 70 3e 49 74 27 73 20 6a 75 73 74 20 61 20 62 75 73 69 6e 65 73 73 20 61 6e 64 20 77 65 20 63 61 72 65 20 6f 6e 6c 79 20 61 62 6f 75 74 20 67 65 74 74 69 6e 67 20 62 65 6e 65 66 69 74 73 2e } //1 <p>It's just a business and we care only about getting benefits.
		$a_01_5 = {54 68 65 20 6f 6e 6c 79 20 77 61 79 20 74 6f 20 67 65 74 20 79 6f 75 72 20 66 69 6c 65 73 20 62 61 63 6b 20 69 73 20 74 6f 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 67 65 74 20 66 75 72 74 68 65 72 20 69 6e 73 74 75 63 74 69 6f 6e 73 2e } //1 The only way to get your files back is to contact us and get further instuctions.
		$a_01_6 = {3c 70 3e 54 6f 20 70 72 6f 76 65 20 74 68 61 74 20 77 65 20 68 61 76 65 20 61 20 64 65 63 72 79 70 74 6f 72 20 73 65 6e 64 20 75 73 20 61 6e 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 20 28 6c 65 73 73 20 74 68 61 6e 20 36 35 30 20 6b 62 79 74 65 73 29 20 61 6e 64 20 77 65 27 6c 6c 20 73 65 6e 64 20 79 6f 75 20 69 74 20 62 61 63 6b 20 62 65 69 6e 67 20 64 65 63 72 79 70 74 65 64 2e } //1 <p>To prove that we have a decryptor send us any encrypted file (less than 650 kbytes) and we'll send you it back being decrypted.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}