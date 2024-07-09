
rule Ransom_Win32_Filecoder_BA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {2e 43 4f 4e 54 49 } //1 .CONTI
		$a_81_1 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } //1 HOW_TO_DECRYPT.txt
		$a_81_2 = {24 52 45 43 59 43 4c 45 2e 42 49 4e } //1 $RECYCLE.BIN
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Ransom_Win32_Filecoder_BA_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 44 41 54 41 20 57 41 53 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR DATA WAS ENCRYPTED
		$a_81_1 = {5f 5f 6c 6f 63 6b 5f 58 58 58 5f 5f } //1 __lock_XXX__
		$a_81_2 = {21 21 21 52 45 41 44 5f 4d 45 21 21 21 2e 74 78 74 } //1 !!!READ_ME!!!.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Ransom_Win32_Filecoder_BA_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 45 41 44 5f 4d 45 2e 74 78 74 } //1 READ_ME.txt
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 30 20 2d 77 20 33 30 30 30 20 3e 20 4e 75 6c 20 26 20 44 65 6c 20 2f 66 20 2f 71 20 22 25 73 22 } //1 cmd.exe /C ping 1.1.1.1 -n 10 -w 3000 > Nul & Del /f /q "%s"
		$a_81_2 = {63 3a 5c 31 31 31 5c 68 65 72 6d 65 73 5c 63 72 79 70 74 6f 70 70 } //2 c:\111\hermes\cryptopp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2) >=3
 
}
rule Ransom_Win32_Filecoder_BA_MTB_4{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 delete shadows /all /quiet
		$a_81_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 } //3 vssadmin.exe
		$a_81_2 = {52 45 41 44 5f 4d 45 2e 54 58 54 } //1 READ_ME.TXT
		$a_81_3 = {48 45 4c 50 5f 50 43 2e 45 5a 44 5a 2d 52 45 4d 4f 56 45 2e 74 78 74 } //1 HELP_PC.EZDZ-REMOVE.txt
		$a_81_4 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 2e 62 69 6e } //1 encrypted_key.bin
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}
rule Ransom_Win32_Filecoder_BA_MTB_5{
	meta:
		description = "Ransom:Win32/Filecoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 } //1 HOW_TO_DECRYPT
		$a_02_1 = {54 00 68 00 65 00 20 00 [0-10] 20 00 69 00 73 00 20 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 } //1
		$a_02_2 = {54 68 65 20 [0-10] 20 69 73 20 4c 4f 43 4b 45 44 } //1
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_4 = {46 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 4b 45 59 20 77 72 69 74 65 20 48 45 52 45 3a } //1 For decryption KEY write HERE:
	condition:
		((#a_81_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}