
rule Ransom_Win32_StopCrypt_ASC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 31 00 20 00 2d 00 77 00 20 00 33 00 30 00 30 00 30 00 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 } //3 cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q
		$a_01_1 = {44 65 63 72 79 70 74 66 69 6c 65 73 2e 74 78 74 } //2 Decryptfiles.txt
		$a_01_2 = {62 6f 6f 74 2e 69 6e 69 64 65 73 6b 74 6f 70 2e 69 6e 69 6e 74 75 73 65 72 2e 64 61 74 69 63 6f 6e 63 61 63 68 65 2e 64 62 62 6f 6f 74 73 65 63 74 2e 62 61 6b 6e 74 75 73 65 72 2e 64 61 74 2e 6c 6f 67 42 6f 6f 74 66 6f 6e 74 2e 62 69 6e 44 65 63 72 79 70 74 66 69 6c 65 73 2e 74 78 74 } //5 boot.inidesktop.inintuser.daticoncache.dbbootsect.bakntuser.dat.logBootfont.binDecryptfiles.txt
		$a_01_3 = {65 64 66 72 37 38 39 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //4 edfr789@tutanota.com
		$a_01_4 = {77 65 20 61 64 76 69 73 65 20 79 6f 75 20 63 6f 6e 74 61 63 74 20 75 73 20 69 6e 20 6c 65 73 73 20 74 68 61 6e 20 37 32 20 68 6f 75 72 73 2c 20 6f 74 68 65 72 77 69 73 65 20 74 68 65 72 65 20 69 73 20 61 20 70 6f 73 73 69 62 69 6c 69 74 79 20 74 68 61 74 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 6e 65 76 65 72 20 62 65 20 72 65 74 75 72 6e 65 64 } //1 we advise you contact us in less than 72 hours, otherwise there is a possibility that your files will never be returned
		$a_01_5 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 20 61 20 64 65 63 72 79 70 74 20 74 6f 6f 6c 2c 20 79 6f 75 20 6d 61 79 20 64 61 6d 61 67 65 20 74 68 65 6d 20 6d 61 6b 69 6e 67 20 74 68 65 6d 20 69 6d 70 6f 73 73 69 62 6c 65 20 74 6f 20 72 65 63 6f 76 65 72 } //1 Do not try to recover your files without a decrypt tool, you may damage them making them impossible to recover
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=16
 
}