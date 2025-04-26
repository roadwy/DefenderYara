
rule Ransom_Win32_Hackrypt_MTB{
	meta:
		description = "Ransom:Win32/Hackrypt!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 61 63 6b 20 46 6f 72 20 4c 69 66 65 } //1 Hack For Life
		$a_01_1 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 48 61 73 20 42 65 65 6e 20 4c 6f 63 6b 65 64 21 } //1 All Your Files Has Been Locked!
		$a_01_2 = {5c 55 6e 6c 6f 63 6b 5f 41 6c 6c 5f 46 69 6c 65 73 2e 74 78 74 } //1 \Unlock_All_Files.txt
		$a_01_3 = {46 69 6c 65 55 6e 6c 6f 63 6b 46 69 6c 65 45 78 5c 45 6e 63 72 79 70 74 2e 65 78 65 } //1 FileUnlockFileEx\Encrypt.exe
		$a_03_4 = {43 6f 6e 74 61 63 74 20 3a 20 [0-10] 40 67 6d 61 69 6c 2e 63 6f 6d 20 6f 72 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 66 69 6c 65 64 65 63 72 79 70 74 30 30 32 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}