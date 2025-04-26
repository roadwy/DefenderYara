
rule Ransom_Win64_FalconCrypt_YAB_MTB{
	meta:
		description = "Ransom:Win64/FalconCrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 63 72 79 70 74 2e 70 64 62 } //1 malcrypt.pdb
		$a_01_1 = {6c 69 62 72 61 72 79 5c 63 6f 72 65 5c 73 72 63 5c 65 73 63 61 70 65 2e 72 73 } //1 library\core\src\escape.rs
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 66 61 6c 63 6f 6e 44 65 73 6b 74 6f 70 65 6e 63 72 79 70 74 69 6f 6e 5f 6e 6f 74 65 2e 74 78 74 } //1 C:\Users\falconDesktopencryption_note.txt
		$a_01_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 4d 61 6c 63 72 79 70 74 } //1 Your files have been encrypted by Malcrypt
		$a_01_4 = {79 6f 75 20 6d 75 73 74 20 70 61 79 20 61 20 72 61 6e 73 6f 6d 20 6f 66 } //1 you must pay a ransom of
		$a_01_5 = {54 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 66 6f 6c 6c 6f 77 20 74 68 65 73 65 20 73 74 65 70 73 } //1 To unlock your files, follow these steps
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}