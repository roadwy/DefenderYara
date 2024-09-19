
rule Ransom_Win32_Royal_SA{
	meta:
		description = "Ransom:Win32/Royal.SA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 6f 00 79 00 61 00 6c 00 5f 00 } //5 .royal_
		$a_01_1 = {72 6f 79 61 6c 5f 64 6c 6c 2e 64 6c 6c } //5 royal_dll.dll
		$a_01_2 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 54 00 58 00 54 00 } //2 README.TXT
		$a_01_3 = {2d 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 6f 00 6e 00 6c 00 79 00 } //2 -networkonly
		$a_01_4 = {2d 00 6c 00 6f 00 63 00 61 00 6c 00 6f 00 6e 00 6c 00 79 00 } //2 -localonly
		$a_01_5 = {49 66 20 79 6f 75 20 61 72 65 20 72 65 61 64 69 6e 67 20 74 68 69 73 2c 20 69 74 20 6d 65 61 6e 73 20 74 68 61 74 20 79 6f 75 72 20 73 79 73 74 65 6d 20 77 65 72 65 20 68 69 74 20 62 79 20 52 6f 79 61 6c 20 72 61 6e 73 6f 6d 77 61 72 65 2e } //5 If you are reading this, it means that your system were hit by Royal ransomware.
		$a_01_6 = {54 72 79 20 52 6f 79 61 6c 20 74 6f 64 61 79 20 61 6e 64 20 65 6e 74 65 72 20 74 68 65 20 6e 65 77 20 65 72 61 20 6f 66 20 64 61 74 61 20 73 65 63 75 72 69 74 79 21 } //5 Try Royal today and enter the new era of data security!
		$a_01_7 = {68 74 74 70 3a 2f 2f 72 6f 79 61 6c 32 78 74 68 69 67 33 6f 75 35 68 64 37 7a 73 6c 69 71 61 67 79 36 79 79 67 6b 32 63 64 65 6c 61 78 74 6e 69 32 66 79 61 64 36 64 70 6d 70 78 65 64 69 64 2e 6f 6e 69 6f 6e 2f } //5 http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=10
 
}