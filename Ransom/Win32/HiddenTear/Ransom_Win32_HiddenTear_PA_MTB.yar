
rule Ransom_Win32_HiddenTear_PA_MTB{
	meta:
		description = "Ransom:Win32/HiddenTear.PA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 69 00 79 00 6f 00 72 00 73 00 61 00 6e 00 20 00 4f 00 6b 00 75 00 21 00 21 00 21 00 2e 00 74 00 78 00 74 00 } //1 stiyorsan Oku!!!.txt
		$a_01_1 = {77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 2e 00 62 00 6d 00 70 00 } //1 wallpaper.bmp
		$a_01_2 = {2d 2d 2d 4f 6f 70 73 20 44 6f 73 79 61 6c 61 72 } //1 ---Oops Dosyalar
		$a_01_3 = {69 66 72 65 6c 65 6e 64 69 21 2d 2d 2d } //1 ifrelendi!---
		$a_01_4 = {73 61 63 61 20 34 30 30 20 3d 20 44 65 63 72 79 70 74 6f 72 20 4b 61 70 69 } //1 saca 400 = Decryptor Kapi
		$a_01_5 = {4f 6c 61 6e 20 44 65 63 72 79 70 74 65 72 69 20 53 61 6e 61 20 56 65 72 65 63 65 7a } //1 Olan Decrypteri Sana Verecez
		$a_01_6 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}