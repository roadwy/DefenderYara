
rule Ransom_MacOS_FileCoder_A_MTB{
	meta:
		description = "Ransom:MacOS/FileCoder.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 76 31 32 30 38 2e 6c 6f 63 61 6c 2f 6b 65 79 2e 70 68 70 } //2 dv1208.local/key.php
		$a_00_1 = {2f 44 6f 63 75 6d 65 6e 74 73 2f 53 6b 6f 6c 61 6e 2f 44 56 31 32 30 38 2f 50 72 6f 6a 65 6b 74 2f 45 6e 63 72 79 70 74 46 69 6c 65 73 20 47 55 49 2f 45 6e 63 72 79 70 74 46 69 6c 65 73 47 55 49 2f 50 61 79 6d 65 6e 74 2e 6f } //2 /Documents/Skolan/DV1208/Projekt/EncryptFiles GUI/EncryptFilesGUI/Payment.o
		$a_00_2 = {2f 45 6e 63 72 79 70 74 46 69 6c 65 73 47 55 49 2f 75 69 5f 44 65 63 72 79 70 74 69 6f 6e 2e 68 } //1 /EncryptFilesGUI/ui_Decryption.h
		$a_00_3 = {3a 2f 69 6d 61 67 65 73 2f 64 65 63 72 79 70 74 69 6e 67 2e 67 69 66 } //1 :/images/decrypting.gif
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}