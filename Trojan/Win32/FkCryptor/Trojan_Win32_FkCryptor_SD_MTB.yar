
rule Trojan_Win32_FkCryptor_SD_MTB{
	meta:
		description = "Trojan:Win32/FkCryptor.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All of your files have been encrypted
		$a_01_1 = {57 65 6c 6c 20 74 68 61 74 27 73 20 77 68 61 74 20 68 61 70 70 65 6e 73 20 77 68 65 6e 20 79 6f 75 20 77 61 74 63 68 20 70 6f 72 6e 20 6f 6e 20 73 68 61 64 79 20 73 69 74 65 73 20 6d 61 74 65 } //1 Well that's what happens when you watch porn on shady sites mate
		$a_01_2 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 41 45 53 2d 32 35 36 } //1 All of your personal files have been encrypted with AES-256
		$a_01_3 = {41 6e 64 20 75 6e 6c 69 6b 65 20 6f 74 68 65 72 20 72 61 6e 73 6f 6d 77 61 72 65 20 77 65 20 64 6f 6e 27 74 20 77 61 6e 74 20 79 6f 75 20 74 6f 20 70 61 79 20 75 73 20 61 6e 79 74 68 69 6e 67 } //1 And unlike other ransomware we don't want you to pay us anything
		$a_01_4 = {41 6c 6c 20 79 6f 75 20 68 61 76 65 20 74 6f 20 64 6f 20 69 73 20 63 6c 69 63 6b 20 74 68 65 20 22 49 27 6d 20 67 61 79 22 20 62 75 74 74 6f 6e 20 61 6e 64 20 73 69 74 20 74 68 72 6f 75 67 68 } //1 All you have to do is click the "I'm gay" button and sit through
		$a_01_5 = {49 66 20 79 6f 75 27 72 65 20 74 68 69 6e 6b 69 6e 67 20 61 62 6f 75 74 20 63 68 65 61 74 69 6e 67 20 2d 20 64 6f 6e 27 74 2e 20 57 65 20 77 69 6c 6c 20 64 65 74 65 63 74 20 74 68 61 74 } //1 If you're thinking about cheating - don't. We will detect that
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}