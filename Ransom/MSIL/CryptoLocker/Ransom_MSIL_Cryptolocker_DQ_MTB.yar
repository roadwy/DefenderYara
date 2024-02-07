
rule Ransom_MSIL_Cryptolocker_DQ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 10 00 00 32 00 "
		
	strings :
		$a_81_0 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 } //32 00  NitroRansomware
		$a_81_1 = {66 72 69 65 6e 64 6c 79 2e 63 79 62 65 72 2e 63 72 69 6d 69 6e 61 6c } //32 00  friendly.cyber.criminal
		$a_81_2 = {49 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 31 20 66 69 6c 65 20 6f 6e 20 79 6f 75 72 20 64 65 73 6b 74 6f 70 } //32 00  I will delete 1 file on your desktop
		$a_81_3 = {54 68 69 73 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 68 61 63 6b 65 64 } //14 00  This computer has been hacked
		$a_81_4 = {2e 67 69 76 65 6d 65 6e 69 74 72 6f } //14 00  .givemenitro
		$a_81_5 = {73 6c 61 6d 72 61 6e 73 6f 6d 77 61 72 65 61 73 69 73 74 61 6e 63 65 } //14 00  slamransomwareasistance
		$a_81_6 = {2e 64 65 72 69 61 } //14 00  .deria
		$a_81_7 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 63 72 79 70 74 65 64 } //03 00  Your personal files have been ecrypted
		$a_81_8 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 63 72 79 70 74 65 64 } //03 00  Your files have been crypted
		$a_81_9 = {45 6e 63 72 79 70 74 46 69 6c 65 } //03 00  EncryptFile
		$a_81_10 = {53 79 73 74 65 6d 4c 6f 63 6b 65 72 } //03 00  SystemLocker
		$a_81_11 = {52 45 41 44 5f 49 54 2e 74 78 74 2e 6c 6f 63 6b 65 64 } //01 00  READ_IT.txt.locked
		$a_81_12 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 3a } //01 00  Decryption Key:
		$a_81_13 = {41 45 53 5f 45 6e 63 72 79 70 74 } //01 00  AES_Encrypt
		$a_81_14 = {6e 63 72 79 70 74 65 64 20 79 6f 75 72 } //01 00  ncrypted your
		$a_81_15 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //00 00  ransom.jpg
	condition:
		any of ($a_*)
 
}