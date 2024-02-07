
rule Ransom_Win32_Cryptolocker_PDR_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {62 61 62 79 44 6f 6e 74 48 65 61 72 74 4d 65 } //01 00  babyDontHeartMe
		$a_81_1 = {77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 } //01 00  we can decrypt one file
		$a_81_2 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //01 00  @tutanota.com
		$a_81_3 = {54 6f 72 20 42 72 6f 77 73 65 72 } //00 00  Tor Browser
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_2{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 75 63 6b 79 6f 75 } //01 00  fuckyou
		$a_81_1 = {44 65 63 72 79 70 74 2d 6d 65 } //01 00  Decrypt-me
		$a_81_2 = {72 65 63 6f 76 65 72 66 69 6c 65 73 } //01 00  recoverfiles
		$a_81_3 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //01 00  recoveryenabled no
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 6d 67 72 } //00 00  DisableTaskmgr
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_3{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files were encrypted
		$a_81_1 = {54 6f 75 63 68 4d 65 4e 6f 74 } //01 00  TouchMeNot
		$a_81_2 = {2e 43 72 59 70 54 65 44 } //01 00  .CrYpTeD
		$a_81_3 = {64 65 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //00 00  decrypted successfully
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_4{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  files were encrypted
		$a_81_1 = {41 45 53 2d 32 35 36 20 4d 49 4c 4c 49 54 41 52 59 } //01 00  AES-256 MILLITARY
		$a_81_2 = {52 45 53 54 4f 52 45 20 47 45 54 20 42 41 43 4b 20 59 4f 55 52 20 46 49 4c 45 53 } //01 00  RESTORE GET BACK YOUR FILES
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //00 00  @protonmail.com
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Cryptolocker_PDR_MTB_5{
	meta:
		description = "Ransom:Win32/Cryptolocker.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //01 00  /c vssadmin.exe delete shadows /all /quiet
		$a_81_1 = {42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 } //01 00  BEGIN PUBLIC KEY
		$a_81_2 = {42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 } //01 00  BEGIN RSA PRIVATE KEY
		$a_81_3 = {42 41 53 45 36 34 45 4e 43 52 59 50 54 45 44 } //00 00  BASE64ENCRYPTED
	condition:
		any of ($a_*)
 
}