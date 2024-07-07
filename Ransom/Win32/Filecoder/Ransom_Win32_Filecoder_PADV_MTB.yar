
rule Ransom_Win32_Filecoder_PADV_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PADV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 4c 6f 63 6b 65 72 } //1 NanoLocker
		$a_01_1 = {57 65 20 72 65 63 6f 6d 6d 65 6e 64 20 74 6f 20 79 6f 75 20 74 75 72 6e 20 6f 66 66 20 6f 72 20 64 69 73 61 62 6c 65 20 61 6c 6c 20 61 6e 74 69 76 69 72 75 73 20 61 6e 64 20 75 73 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 6f 6e 6c 79 20 66 6f 72 20 73 65 6e 64 69 6e 67 20 6d 6f 6e 65 79 20 75 6e 74 69 6c 20 64 65 63 72 79 70 74 69 6f 6e 20 64 6f 65 73 20 6e 6f 74 20 63 6f 6d 70 6c 65 74 65 } //1 We recommend to you turn off or disable all antivirus and use your computer only for sending money until decryption does not complete
		$a_01_2 = {55 73 69 6e 67 20 61 6e 79 20 74 68 69 72 64 2d 70 61 72 74 79 20 43 72 79 70 74 6f 72 2c 20 41 6e 74 69 6d 61 6c 77 61 72 65 20 6f 72 20 41 6e 74 69 4c 6f 63 6b 65 72 20 63 61 6e 20 64 65 73 74 72 6f 79 20 74 68 69 73 20 44 65 63 72 79 70 74 6f 72 20 61 6e 64 20 4c 4f 53 45 20 41 4c 4c 20 59 4f 55 52 20 44 41 54 41 20 46 4f 52 45 56 45 52 } //1 Using any third-party Cryptor, Antimalware or AntiLocker can destroy this Decryptor and LOSE ALL YOUR DATA FOREVER
		$a_01_3 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}