
rule Ransom_Win32_Filecoder_PAHX_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //2 YOUR FILES ARE ENCRYPTED
		$a_01_1 = {44 69 73 63 6f 76 65 72 65 64 20 61 20 73 65 72 69 6f 75 73 20 76 75 6c 6e 65 72 61 62 69 6c 69 74 79 20 69 6e 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 73 65 63 75 72 69 74 79 } //1 Discovered a serious vulnerability in your network security
		$a_01_2 = {44 6f 20 6e 6f 74 20 61 74 74 65 6d 70 74 20 74 6f 20 72 65 6d 6f 76 65 20 74 68 65 20 70 72 6f 67 72 61 6d 20 6f 72 20 72 75 6e 20 74 68 65 20 61 6e 74 69 2d 76 69 72 75 73 20 74 6f 6f 6c 73 } //1 Do not attempt to remove the program or run the anti-virus tools
		$a_01_3 = {41 74 74 65 6d 70 74 73 20 74 6f 20 73 65 6c 66 2d 64 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 74 68 65 20 6c 6f 73 73 20 6f 66 20 79 6f 75 72 20 64 61 74 61 } //2 Attempts to self-decrypting files will result in the loss of your data
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}