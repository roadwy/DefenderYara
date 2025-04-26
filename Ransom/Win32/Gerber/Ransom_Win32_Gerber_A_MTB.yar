
rule Ransom_Win32_Gerber_A_MTB{
	meta:
		description = "Ransom:Win32/Gerber.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 28 6f 72 20 73 65 72 76 65 72 29 20 69 73 20 62 6c 6f 63 6b 65 64 20 62 79 20 47 65 72 62 65 72 20 34 20 64 75 65 20 61 20 73 65 63 75 72 69 74 79 20 72 65 61 73 6f 6e 73 } //1 Your computer (or server) is blocked by Gerber 4 due a security reasons
		$a_01_1 = {44 6f 6e 27 74 20 77 6f 72 72 79 2c 20 69 66 20 79 6f 75 72 20 66 69 6c 65 73 20 67 65 74 20 61 20 6e 65 77 20 65 78 74 65 6e 73 69 6f 6e } //1 Don't worry, if your files get a new extension
		$a_01_2 = {43 6f 6e 74 61 63 74 20 74 6f 20 65 6d 61 69 6c 20 61 64 64 72 65 73 73 3a 20 6d 65 6d 6f 79 61 6e 6f 76 2e 61 72 74 75 72 37 39 40 63 6f 63 6b 2e 6c 69 20 6f 72 20 62 65 73 74 6c 65 76 65 6c 64 61 79 70 61 79 64 61 79 40 63 6f 63 6b 2e 6c 69 } //1 Contact to email address: memoyanov.artur79@cock.li or bestleveldaypayday@cock.li
		$a_01_3 = {57 61 72 6e 69 6e 67 3a 20 59 6f 75 20 63 61 6e 27 74 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 20 6e 6f 74 65 3a 20 44 65 63 72 79 70 74 2e 54 58 54 } //1 Warning: You can't decrypt files without note: Decrypt.TXT
		$a_01_4 = {43 6f 6e 74 61 63 74 20 74 6f 20 65 6d 61 69 6c 20 61 64 64 72 65 73 73 3a 20 6d 65 6d 6f 79 61 6e 6f 76 2e 61 72 74 75 72 37 39 40 62 69 74 6d 65 73 73 61 67 65 2e 63 68 20 6f 72 20 62 65 73 74 6c 65 76 65 6c 64 61 79 70 61 79 64 61 79 40 62 69 74 6d 65 73 73 61 67 65 2e 63 68 } //1 Contact to email address: memoyanov.artur79@bitmessage.ch or bestleveldaypayday@bitmessage.ch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}