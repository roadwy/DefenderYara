
rule Ransom_Win32_FileCrypt_AI_MTB{
	meta:
		description = "Ransom:Win32/FileCrypt.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 44 65 66 61 75 6c 74 2e 72 64 70 } //1 del Default.rdp
		$a_01_1 = {48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 59 5f 46 49 4c 45 53 2e 74 78 74 } //1 HOW_TO_RECOVERY_FILES.txt
		$a_01_2 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 49 44 3a } //1 Your personal ID:
		$a_01_3 = {48 45 4c 4c 4f 2c 20 48 4f 57 20 41 52 45 20 59 4f 55 3f } //1 HELLO, HOW ARE YOU?
		$a_01_4 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your data are stolen and encrypted!
		$a_01_5 = {59 6f 75 20 63 61 6e 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //1 You can contact us and decrypt one file for free
		$a_01_6 = {68 65 6c 6c 6f 68 6f 77 61 72 65 79 6f 75 40 63 6f 63 6b 2e 6c 69 } //1 hellohowareyou@cock.li
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}