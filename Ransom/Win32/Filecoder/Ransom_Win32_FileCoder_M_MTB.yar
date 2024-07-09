
rule Ransom_Win32_FileCoder_M_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 2c e4 09 c5 83 e7 00 31 ef 5d 6a 00 89 14 e4 31 d2 31 fa 89 93 ?? ?? ?? ?? 5a 89 45 fc 2b 45 fc 0b 83 ?? ?? ?? ?? 83 e6 00 31 c6 8b 45 fc 89 7d f8 29 ff 0b bb ?? ?? ?? ?? 89 f9 8b 7d f8 fc f3 a4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Ransom_Win32_FileCoder_M_MTB_2{
	meta:
		description = "Ransom:Win32/FileCoder.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 57 4d 20 2f 46 } //schtasks /delete /tn WM /F  1
		$a_80_1 = {52 65 63 6f 76 65 72 79 20 79 6f 75 72 20 66 69 6c 65 73 } //Recovery your files  1
		$a_80_2 = {49 20 61 6d 20 73 6f 20 73 6f 72 72 79 20 21 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 64 20 62 79 20 52 53 41 2d 31 30 32 34 20 61 6e 64 20 41 45 53 2d 32 35 36 20 64 75 65 20 74 6f 20 61 20 63 6f 6d 70 75 74 65 72 20 73 65 63 75 72 69 74 79 20 70 72 6f 62 6c 65 6d 73 } //I am so sorry ! All your files have been encryptd by RSA-1024 and AES-256 due to a computer security problems  1
		$a_80_3 = {54 68 65 20 6f 6e 6c 79 20 77 61 79 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 20 69 73 20 74 6f 20 62 75 79 20 6d 79 20 64 65 63 72 79 74 69 6f 6e 20 74 6f 6f 6c } //The only way to decrypt your file is to buy my decrytion tool  1
		$a_80_4 = {59 6f 75 72 20 70 65 72 73 6f 6e 69 64 20 3a } //Your personid :  1
		$a_80_5 = {73 65 6e 64 20 49 54 53 42 54 43 20 62 74 63 20 74 6f 20 6d 79 20 77 61 6c 6c 65 74 20 61 64 64 72 65 73 73 20 49 54 53 41 44 44 52 } //send ITSBTC btc to my wallet address ITSADDR  1
		$a_80_6 = {66 69 6e 61 6c 6c 79 20 79 6f 75 20 77 69 6c 6c 20 6b 6f 77 6e 20 69 74 27 73 20 76 61 69 6e } //finally you will kown it's vain  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}