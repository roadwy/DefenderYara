
rule Ransom_MSIL_Cryptolocker_PDL_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your system have been encrypted
		$a_81_1 = {72 61 6e 64 6f 6d 6b 65 79 2e 62 69 6e } //1 randomkey.bin
		$a_81_2 = {2e 52 45 4e 53 45 4e 57 41 52 45 } //1 .RENSENWARE
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 } //1 Decrypt My Files
		$a_81_1 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //1 ransom.jpg
		$a_81_2 = {2e 43 72 79 70 74 65 64 } //1 .Crypted
		$a_81_3 = {4e 6f 20 66 69 6c 65 73 20 64 65 63 72 79 70 74 65 64 } //1 No files decrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_3{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4e 6f 20 66 69 6c 65 73 20 74 6f 20 65 6e 63 72 79 70 74 } //1 No files to encrypt
		$a_81_1 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //1 RECOVER__FILES
		$a_81_2 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 have been encrypted
		$a_81_3 = {2e 6e 63 6f 76 69 64 } //1 .ncovid
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_4{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 65 20 68 61 76 65 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 all your important filese have are encrypted
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 } //1 Ransomware
		$a_81_2 = {2e 4c 6f 63 6b } //1 .Lock
		$a_81_3 = {2e 6f 6e 69 6f 6e } //1 .onion
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_5{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 43 20 73 63 20 64 65 6c 65 74 65 20 56 53 53 } //1 /C sc delete VSS
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {6b 57 59 5a 72 7a 49 59 5a 52 2e 68 74 6d 6c } //1 kWYZrzIYZR.html
		$a_81_3 = {72 64 70 75 6e 6c 6f 63 6b 65 72 31 40 63 6f 63 6b 2e 6c 69 } //1 rdpunlocker1@cock.li
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_6{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 61 72 65 20 66 6f 72 6d 61 74 74 65 64 } //1 All encrypted files are formatted
		$a_81_1 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 } //1 HOW TO DECRYPT FILES
		$a_81_2 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //1 ransom.jpg
		$a_81_3 = {2e 43 72 79 70 74 65 64 } //1 .Crypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_7{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 4f 57 5f 43 41 4e 5f 47 45 54 5f 46 49 4c 45 53 5f 42 41 43 4b } //1 HOW_CAN_GET_FILES_BACK
		$a_81_1 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 46 69 6e 69 73 68 65 64 } //1 Delete Shadows Finished
		$a_81_2 = {57 68 61 74 20 54 68 65 20 46 75 63 6b } //1 What The Fuck
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_PDL_MTB_8{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 encrypted files
		$a_81_1 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 decrypt your files
		$a_81_2 = {2f 43 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /C vssadmin.exe delete shadows /all /quiet
		$a_81_3 = {52 45 41 44 5f 4d 45 5f 46 49 4c 45 5f 45 4e 43 52 59 50 54 45 44 } //1 READ_ME_FILE_ENCRYPTED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}