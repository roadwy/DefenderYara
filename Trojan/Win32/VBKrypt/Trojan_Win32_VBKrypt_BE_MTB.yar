
rule Trojan_Win32_VBKrypt_BE_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BE!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 6e 00 73 00 65 00 6b 00 72 00 65 00 6d 00 65 00 6e 00 } //1 rensekremen
		$a_01_1 = {46 00 79 00 6c 00 64 00 65 00 72 00 69 00 73 00 74 00 65 00 72 00 6e 00 65 00 33 00 } //1 Fylderisterne3
		$a_01_2 = {4f 00 56 00 45 00 52 00 4d 00 41 00 4e 00 41 00 47 00 45 00 44 00 } //1 OVERMANAGED
		$a_01_3 = {42 41 4e 54 41 4d 4b } //1 BANTAMK
		$a_01_4 = {44 69 72 65 6b 74 6f 72 } //1 Direktor
		$a_01_5 = {41 41 52 53 41 47 53 42 } //1 AARSAGSB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_VBKrypt_BE_MTB_2{
	meta:
		description = "Trojan:Win32/VBKrypt.BE!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 48 00 4e 00 4c 00 41 00 62 00 2c 00 20 00 49 00 4e 00 43 00 } //1 AHNLAb, INC
		$a_01_1 = {4d 00 41 00 4b 00 41 00 79 00 61 00 6d 00 61 00 20 00 49 00 4e 00 54 00 45 00 72 00 61 00 63 00 74 00 69 00 76 00 65 00 } //1 MAKAyama INTEractive
		$a_01_2 = {49 00 54 00 49 00 42 00 69 00 74 00 69 00 20 00 49 00 4e 00 43 00 } //1 ITIBiti INC
		$a_01_3 = {45 00 41 00 53 00 59 00 2d 00 48 00 49 00 44 00 45 00 2d 00 49 00 70 00 20 00 76 00 70 00 6e 00 } //1 EASY-HIDE-Ip vpn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}