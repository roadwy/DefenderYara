
rule Ransom_Win32_Cryptolocker_PDR_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 61 62 79 44 6f 6e 74 48 65 61 72 74 4d 65 } //1 babyDontHeartMe
		$a_81_1 = {77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 } //1 we can decrypt one file
		$a_81_2 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 @tutanota.com
		$a_81_3 = {54 6f 72 20 42 72 6f 77 73 65 72 } //1 Tor Browser
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_2{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 75 63 6b 79 6f 75 } //1 fuckyou
		$a_81_1 = {44 65 63 72 79 70 74 2d 6d 65 } //1 Decrypt-me
		$a_81_2 = {72 65 63 6f 76 65 72 66 69 6c 65 73 } //1 recoverfiles
		$a_81_3 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 recoveryenabled no
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } //1 DisableTaskmgr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_3{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All your files were encrypted
		$a_81_1 = {54 6f 75 63 68 4d 65 4e 6f 74 } //1 TouchMeNot
		$a_81_2 = {2e 43 72 59 70 54 65 44 } //1 .CrYpTeD
		$a_81_3 = {64 65 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 decrypted successfully
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_4{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 files were encrypted
		$a_81_1 = {41 45 53 2d 32 35 36 20 4d 49 4c 4c 49 54 41 52 59 } //1 AES-256 MILLITARY
		$a_81_2 = {52 45 53 54 4f 52 45 20 47 45 54 20 42 41 43 4b 20 59 4f 55 52 20 46 49 4c 45 53 } //1 RESTORE GET BACK YOUR FILES
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_5{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /c vssadmin.exe delete shadows /all /quiet
		$a_81_1 = {42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 } //1 BEGIN PUBLIC KEY
		$a_81_2 = {42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 } //1 BEGIN RSA PRIVATE KEY
		$a_81_3 = {42 41 53 45 36 34 45 4e 43 52 59 50 54 45 44 } //1 BASE64ENCRYPTED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}