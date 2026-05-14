
rule Ransom_Win32_GandCrab_SX_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 03 00 00 "
		
	strings :
		$a_80_0 = {47 61 6e 64 43 72 61 62 20 44 65 63 72 79 70 74 6f 72 } //GandCrab Decryptor  10
		$a_80_1 = {64 65 63 72 79 70 74 69 6f 6e 5f 6c 6f 67 5f 75 74 66 31 36 2e 74 78 74 } //decryption_log_utf16.txt  5
		$a_80_2 = {4b 65 79 20 68 61 73 20 62 65 65 6e 20 64 65 63 6f 64 65 64 } //Key has been decoded  2
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*2) >=17
 
}