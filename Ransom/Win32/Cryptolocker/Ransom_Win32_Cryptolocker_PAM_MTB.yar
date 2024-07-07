
rule Ransom_Win32_Cryptolocker_PAM_MTB{
	meta:
		description = "Ransom:Win32/Cryptolocker.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6f 6f 64 20 4c 75 63 6b 21 } //1 Good Luck!
		$a_01_1 = {4c 6f 63 6b 69 74 40 73 74 64 } //1 Lockit@std
		$a_01_2 = {43 48 45 43 4b 5f 59 4f 55 52 5f 46 49 4c 45 53 5f 4e 4f 57 5f 4c 4f 4c 4f 4c } //1 CHECK_YOUR_FILES_NOW_LOLOL
		$a_01_3 = {59 6f 75 20 64 6f 6e 27 74 20 68 61 76 65 20 61 6e 79 74 68 69 6e 67 20 6d 6f 72 65 20 74 6f 20 64 6f 21 } //1 You don't have anything more to do!
		$a_01_4 = {48 65 6c 6c 6f 20 73 69 72 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 61 73 20 62 65 65 6e 20 72 69 70 70 65 64 20 6f 66 66 } //1 Hello sir, your files was been ripped off
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}