
rule Ransom_Win32_Cyanmischa_MKV_MTB{
	meta:
		description = "Ransom:Win32/Cyanmischa.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 59 41 4e 4d 49 53 43 48 41 20 52 41 4e 53 4f 4d 57 41 52 45 20 50 45 52 46 43 20 46 49 4c 45 21 21 } //1 CYANMISCHA RANSOMWARE PERFC FILE!!
		$a_01_1 = {59 6f 75 20 62 65 63 61 6d 65 20 76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 43 59 41 4e 4d 49 53 43 48 41 20 52 41 4e 53 4f 4d 57 41 52 45 21 21 21 } //1 You became victim of the CYANMISCHA RANSOMWARE!!!
		$a_01_2 = {66 69 6c 65 73 20 69 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 62 65 65 6e 20 73 61 66 65 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 63 79 61 6e 6d 69 73 63 68 61 } //1 files in your computer have been safely encrypted by cyanmischa
		$a_01_3 = {46 69 6e 61 6c 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 Final decryption key
		$a_01_4 = {63 79 61 6e 6d 69 73 63 68 61 20 64 65 63 72 79 70 74 65 64 } //1 cyanmischa decrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}