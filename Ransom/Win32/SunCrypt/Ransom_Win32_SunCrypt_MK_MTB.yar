
rule Ransom_Win32_SunCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/SunCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0c 00 00 "
		
	strings :
		$a_81_0 = {2d 6e 6f 73 68 61 72 65 73 } //2 -noshares
		$a_81_1 = {2d 6e 6f 6d 75 74 65 78 } //2 -nomutex
		$a_81_2 = {2d 6e 6f 72 65 70 6f 72 74 } //2 -noreport
		$a_81_3 = {2d 6e 6f 73 65 72 76 69 63 65 73 } //2 -noservices
		$a_81_4 = {2d 61 6c 6c } //2 -all
		$a_81_5 = {2d 61 67 72 } //2 -agr
		$a_81_6 = {2d 70 61 74 68 } //2 -path
		$a_81_7 = {2d 6c 6f 67 } //2 -log
		$a_81_8 = {24 52 65 63 79 63 6c 65 2e 62 69 6e } //10 $Recycle.bin
		$a_81_9 = {59 4f 55 52 5f 46 49 4c 45 53 5f 41 52 45 5f 45 4e 43 52 59 50 54 45 44 2e 48 54 4d 4c } //10 YOUR_FILES_ARE_ENCRYPTED.HTML
		$a_81_10 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //10 expand 32-byte k
		$a_81_11 = {65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //10 expand 16-byte k
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_81_8  & 1)*10+(#a_81_9  & 1)*10+(#a_81_10  & 1)*10+(#a_81_11  & 1)*10) >=50
 
}