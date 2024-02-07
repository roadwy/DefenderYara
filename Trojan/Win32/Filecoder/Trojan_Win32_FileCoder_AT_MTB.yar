
rule Trojan_Win32_FileCoder_AT_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 69 6e 66 6f 5d 20 66 69 6c 65 20 65 6e 63 72 79 70 74 61 62 6c 65 20 66 6f 75 6e 64 20 3a 20 25 73 } //01 00  [info] file encryptable found : %s
		$a_01_1 = {5b 69 6e 66 6f 5d 20 65 6e 74 65 72 69 6e 67 20 74 68 65 20 66 6f 6c 64 65 72 20 3a 20 25 73 } //01 00  [info] entering the folder : %s
		$a_01_2 = {45 4e 43 52 59 50 54 4f 52 20 76 30 2e 35 } //01 00  ENCRYPTOR v0.5
		$a_01_3 = {5b 65 72 72 6f 72 5d 20 63 61 6e 27 74 20 72 65 61 64 20 74 68 65 20 6b 65 79 2d 66 69 6c 65 20 3a 73 } //01 00  [error] can't read the key-file :s
		$a_01_4 = {6b 65 79 2e 74 78 74 } //01 00  key.txt
		$a_01_5 = {66 6c 61 67 2e 74 78 74 } //01 00  flag.txt
		$a_01_6 = {2a 2a 2a 2a 43 68 69 66 66 72 65 6d 65 6e 74 20 74 65 72 6d 69 6e } //00 00  ****Chiffrement termin
		$a_00_7 = {5d 04 00 } //00 43 
	condition:
		any of ($a_*)
 
}