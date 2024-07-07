
rule Trojan_Win64_Gooxer_A_dha{
	meta:
		description = "Trojan:Win64/Gooxer.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 58 6f 72 44 65 63 6f 64 65 53 74 72 } //1 main.XorDecodeStr
		$a_01_1 = {6d 61 69 6e 2e 41 65 73 45 6e 63 72 79 70 74 } //1 main.AesEncrypt
		$a_01_2 = {6d 61 69 6e 2e 4d 57 6f 72 6b } //1 main.MWork
		$a_01_3 = {6d 61 69 6e 2e 5f 63 67 6f 65 78 70 77 72 61 70 } //1 main._cgoexpwrap
		$a_01_4 = {6d 61 69 6e 2e 47 5f 68 6f 73 74 } //1 main.G_host
		$a_01_5 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 32-byte k
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}