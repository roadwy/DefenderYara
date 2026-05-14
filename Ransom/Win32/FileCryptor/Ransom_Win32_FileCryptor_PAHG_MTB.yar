
rule Ransom_Win32_FileCryptor_PAHG_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.PAHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //2 Your files have been encrypted
		$a_01_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 drivers\etc\hosts
		$a_01_2 = {52 45 41 44 5f 4d 45 2e 74 78 74 } //1 READ_ME.txt
		$a_01_3 = {44 4f 20 4e 4f 54 20 52 45 53 54 41 52 54 20 59 4f 55 52 20 43 4f 4d 50 55 54 45 52 } //1 DO NOT RESTART YOUR COMPUTER
		$a_01_4 = {59 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 2c 20 61 6e 64 20 6f 74 68 65 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 20 6c 6f 6e 67 65 72 20 61 63 63 65 73 73 69 62 6c 65 } //1 Your documents, photos, databases, and other files are no longer accessible
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}