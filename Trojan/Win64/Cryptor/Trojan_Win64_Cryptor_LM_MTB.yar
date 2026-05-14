
rule Trojan_Win64_Cryptor_LM_MTB{
	meta:
		description = "Trojan:Win64/Cryptor.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 74 74 65 6d 70 74 73 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 64 61 74 61 20 77 69 74 68 20 74 68 69 72 64 20 70 61 72 74 79 20 73 6f 66 74 77 61 72 65 20 61 73 20 50 68 6f 74 6f 72 65 63 2c 20 52 61 6e 6e 6f 68 44 65 63 72 79 70 74 6f 72 20 65 74 63 2e } //10 Attempts to restore your data with third party software as Photorec, RannohDecryptor etc.
		$a_81_1 = {41 73 20 73 6f 6f 6e 20 61 73 20 77 65 20 72 65 63 65 69 76 65 20 74 68 65 20 70 61 79 6d 65 6e 74 20 79 6f 75 20 77 69 6c 6c 20 67 65 74 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 61 6e 64 } //20 As soon as we receive the payment you will get the decryption tool and
		$a_81_2 = {46 69 6c 65 20 65 6e 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 3a } //5 File encrypted successfully:
		$a_81_3 = {44 4f 20 4e 4f 54 20 4d 4f 56 45 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 2e } //3 DO NOT MOVE the encrypted files.
		$a_81_4 = {53 65 6e 64 20 75 73 20 32 2d 33 20 64 69 66 66 65 72 65 6e 74 20 72 61 6e 64 6f 6d 20 66 69 6c 65 73 20 61 6e 64 20 79 6f 75 20 77 69 6c 6c 20 67 65 74 20 74 68 65 6d 20 64 65 63 72 79 70 74 65 64 2e } //2 Send us 2-3 different random files and you will get them decrypted.
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*20+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=40
 
}