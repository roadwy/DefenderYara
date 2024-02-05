
rule Ransom_Win32_MauriCrypt_MAK_MTB{
	meta:
		description = "Ransom:Win32/MauriCrypt.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 6e 63 72 79 70 74 69 6e 67 20 25 73 } //Encrypting %s  01 00 
		$a_80_1 = {24 52 65 63 79 63 6c 65 2e 42 69 6e } //$Recycle.Bin  01 00 
		$a_80_2 = {46 49 4c 45 53 5f 45 4e 43 52 59 50 54 45 44 2e 68 74 6d 6c } //FILES_ENCRYPTED.html  01 00 
		$a_80_3 = {52 45 41 44 5f 54 4f 5f 44 45 43 52 59 50 54 2e 68 74 6d 6c } //READ_TO_DECRYPT.html  01 00 
		$a_80_4 = {2d 2d 2d 2d 2d 45 4e 44 } //-----END  01 00 
		$a_80_5 = {2d 2d 2d 2d 2d 42 45 47 49 4e } //-----BEGIN  01 00 
		$a_80_6 = {6d 61 73 74 65 72 20 73 65 63 72 65 74 } //master secret  01 00 
		$a_80_7 = {6b 65 79 20 65 78 70 61 6e 73 69 6f 6e } //key expansion  01 00 
		$a_80_8 = {63 6c 69 65 6e 74 20 66 69 6e 69 73 68 65 64 } //client finished  01 00 
		$a_80_9 = {73 65 72 76 65 72 20 66 69 6e 69 73 68 65 64 } //server finished  00 00 
	condition:
		any of ($a_*)
 
}