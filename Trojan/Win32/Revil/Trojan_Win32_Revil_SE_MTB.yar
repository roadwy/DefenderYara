
rule Trojan_Win32_Revil_SE_MTB{
	meta:
		description = "Trojan:Win32/Revil.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 6f 75 62 6c 65 20 72 75 6e 20 6e 6f 74 20 61 6c 6c 6f 77 65 64 21 } //1 Double run not allowed!
		$a_81_1 = {7b 45 58 54 7d 2d 72 65 61 64 6d 65 2e 74 78 74 } //1 {EXT}-readme.txt
		$a_81_2 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 16-byte k
		$a_03_3 = {22 73 75 62 22 3a 22 [0-08] 22 2c 22 64 62 67 22 3a [0-08] 2c 22 65 74 22 3a [0-02] 2c 22 77 69 70 65 22 3a [0-05] 2c 22 77 68 74 22 3a 7b } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}