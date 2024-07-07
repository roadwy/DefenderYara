
rule Ransom_Win32_Lolkek_PA_MTB{
	meta:
		description = "Ransom:Win32/Lolkek.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_02_0 = {83 f8 40 73 90 01 01 8b 45 90 01 01 41 8a 04 10 8b 55 90 01 01 32 04 32 8b 55 90 01 01 88 02 42 8b 45 90 01 01 40 89 55 90 01 01 89 45 90 01 01 3b c7 72 90 00 } //5
		$a_01_1 = {43 52 59 50 54 4f 20 4c 4f 43 4b 45 52 } //5 CRYPTO LOCKER
		$a_01_2 = {2e 00 6c 00 6f 00 6c 00 6b 00 65 00 6b 00 } //1 .lolkek
		$a_01_3 = {4c 00 4f 00 4c 00 4b 00 45 00 4b 00 2e 00 74 00 78 00 74 00 } //1 LOLKEK.txt
		$a_01_4 = {52 00 65 00 61 00 64 00 5f 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 Read_Me.txt
		$a_00_5 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files, documents, photos, databases and other important files are encrypted
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=12
 
}