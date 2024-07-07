
rule Trojan_BAT_Apost_NBL_MTB{
	meta:
		description = "Trojan:BAT/Apost.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {20 53 84 3b cf 66 20 3c 28 ce 10 59 20 97 54 f6 1f 61 20 de 01 aa 19 20 10 2e 73 fa 61 20 bc d4 e7 04 58 20 83 04 c1 e8 61 20 15 bc 90 df 20 bd 33 48 1d 58 65 20 24 10 27 03 59 1f d2 17 63 65 20 26 02 01 fd 20 e2 fd fe 02 58 20 80 00 00 00 1d 63 65 66 } //1
		$a_80_1 = {49 6e 76 6f 6b 65 } //Invoke  1
		$a_80_2 = {43 20 4e 4f 4e 41 2e 65 78 65 } //C NONA.exe  1
		$a_80_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_4 = {73 65 74 5f 4b 65 79 } //set_Key  1
		$a_80_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}