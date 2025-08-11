
rule Ransom_Win64_Petya_MKV_MTB{
	meta:
		description = "Ransom:Win64/Petya.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //1 Your Files Have Been Encrypted
		$a_81_1 = {66 69 6c 65 73 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 6d 69 6c 69 74 61 72 79 2d 67 72 61 64 65 20 41 45 53 2d 32 35 36 20 65 6e 63 72 79 70 74 69 6f 6e } //1 files on this computer have been encrypted using military-grade AES-256 encryption
		$a_81_2 = {44 6f 20 6e 6f 74 20 61 74 74 65 6d 70 74 20 74 6f 20 75 73 65 20 74 68 69 72 64 2d 70 61 72 74 79 20 72 65 63 6f 76 65 72 79 20 74 6f 6f 6c 73 } //1 Do not attempt to use third-party recovery tools
		$a_81_3 = {63 6f 72 72 75 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 70 65 72 6d 61 6e 65 6e 74 6c 79 } //1 corrupt your files permanently
		$a_81_4 = {43 6f 6e 74 61 63 74 20 75 73 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 Contact us for decryption key
		$a_81_5 = {44 6f 20 6e 6f 74 20 73 68 75 74 20 64 6f 77 6e 20 6f 72 20 6d 6f 64 69 66 79 20 74 68 69 73 20 70 72 6f 67 72 61 6d } //1 Do not shut down or modify this program
		$a_81_6 = {50 65 74 79 61 58 57 50 46 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 2d 77 69 6e 64 6f 77 73 5c 77 69 6e 2d 78 36 34 5c 50 65 74 79 61 58 2e 70 64 62 } //4 PetyaXWPF\obj\Release\net8.0-windows\win-x64\PetyaX.pdb
		$a_81_7 = {44 65 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 } //1 Decryption complete
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*4+(#a_81_7  & 1)*1) >=11
 
}