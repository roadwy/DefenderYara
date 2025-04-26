
rule Ransom_Win32_HwruGo_SV_MTB{
	meta:
		description = "Ransom:Win32/HwruGo.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_81_0 = {57 65 20 77 6f 75 6c 64 20 73 68 61 72 65 20 79 6f 75 72 20 53 45 4e 53 49 54 49 56 45 20 44 41 54 41 20 69 6e 20 63 61 73 65 20 79 6f 75 20 72 65 66 75 73 65 20 74 6f 20 70 61 79 } //1 We would share your SENSITIVE DATA in case you refuse to pay
		$a_81_1 = {41 4e 59 20 41 54 54 45 4d 50 54 20 54 4f 20 52 45 53 54 4f 52 45 20 59 4f 55 52 20 46 49 4c 45 53 20 57 49 54 48 20 54 48 49 52 44 2d 50 41 52 54 59 20 53 4f 46 54 57 41 52 45 20 57 49 4c 4c 20 50 45 52 4d 41 4e 45 4e 54 4c 59 20 43 4f 52 52 55 50 54 20 49 54 } //1 ANY ATTEMPT TO RESTORE YOUR FILES WITH THIRD-PARTY SOFTWARE WILL PERMANENTLY CORRUPT IT
		$a_81_2 = {44 4f 20 4e 4f 54 20 4d 4f 44 49 46 59 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //1 DO NOT MODIFY ENCRYPTED FILES
		$a_81_3 = {44 4f 20 4e 4f 54 20 52 45 4e 41 4d 45 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //1 DO NOT RENAME ENCRYPTED FILES
		$a_81_4 = {42 75 74 20 6b 65 65 70 20 63 61 6c 6d 21 20 54 68 65 72 65 20 69 73 20 61 20 73 6f 6c 75 74 69 6f 6e 20 66 6f 72 20 79 6f 75 72 20 70 72 6f 62 6c 65 6d 21 } //1 But keep calm! There is a solution for your problem!
		$a_81_5 = {46 6f 72 20 73 6f 6d 65 20 6d 6f 6e 65 79 20 72 65 77 61 72 64 20 77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 For some money reward we can decrypt all your encrypted files
		$a_81_6 = {41 6c 73 6f 20 77 65 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 20 79 6f 75 72 20 70 72 69 76 61 74 65 20 64 61 74 61 20 66 72 6f 6d 20 6f 75 72 20 73 65 72 76 65 72 73 } //1 Also we will delete all your private data from our servers
		$a_81_7 = {54 6f 20 70 72 6f 76 65 20 74 68 61 74 20 77 65 20 61 72 65 20 61 62 6c 65 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 20 67 69 76 65 20 79 6f 75 20 74 68 65 20 61 62 69 6c 69 74 79 20 74 6f 20 64 65 63 72 79 70 74 20 32 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 } //1 To prove that we are able to decrypt your files we give you the ability to decrypt 2 files for free
		$a_81_8 = {53 6f 20 77 68 61 74 20 69 73 20 79 6f 75 20 6e 65 78 74 20 73 74 65 70 20 3f 20 43 6f 6e 74 61 63 74 20 75 73 20 66 6f 72 20 70 72 69 63 65 20 61 6e 64 20 67 65 74 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 73 6f 66 74 77 61 72 65 } //1 So what is you next step ? Contact us for price and get the decryption software
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=7
 
}