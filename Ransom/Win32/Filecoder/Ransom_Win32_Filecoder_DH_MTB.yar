
rule Ransom_Win32_Filecoder_DH_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 63 72 79 70 74 } //1 .crypt
		$a_81_1 = {4f 72 69 67 69 6e 61 6c 20 46 69 6c 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 6c 65 74 65 64 } //1 Original File successfully deleted
		$a_81_2 = {52 41 4e 53 4f 4d 2e 74 78 74 } //1 RANSOM.txt
		$a_81_3 = {50 41 59 20 4d 45 20 42 49 54 43 4f 49 4e } //1 PAY ME BITCOIN
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Filecoder_DH_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4f 6f 6f 70 73 2c 20 79 6f 75 72 20 68 6f 6d 65 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Ooops, your homework has been encrypted!
		$a_81_1 = {57 61 6e 6e 61 44 65 63 72 79 70 74 6f 72 } //1 WannaDecryptor
		$a_81_2 = {2e 73 68 69 74 } //1 .shit
		$a_81_3 = {65 6e 63 72 79 70 74 46 69 6c 65 4e 61 6d 65 } //1 encryptFileName
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Filecoder_DH_MTB_3{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 6f 77 5f 5f 74 6f 5f 5f 64 65 63 72 79 70 74 5f 5f 66 69 6c 65 73 2e 74 78 74 } //1 How__to__decrypt__files.txt
		$a_81_1 = {49 54 45 52 41 54 4f 52 20 4c 49 53 54 20 43 4f 52 52 55 50 54 45 44 21 } //1 ITERATOR LIST CORRUPTED!
		$a_81_2 = {73 69 63 63 6b 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 sicck@protonmail.com
		$a_81_3 = {42 54 43 20 57 61 6c 6c 65 74 20 3a } //1 BTC Wallet :
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Filecoder_DH_MTB_4{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } //1 cmd.exe /c taskkill /f /im
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 3e 6e 75 6c 20 26 20 64 65 6c 20 2f 71 } //1 cmd.exe /c ping 127.0.0.1>nul & del /q
		$a_81_2 = {63 72 79 5f 64 65 6d 6f 2e 64 6c 6c } //1 cry_demo.dll
		$a_81_3 = {63 6d 64 5f 73 68 61 64 6f 77 } //1 cmd_shadow
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Filecoder_DH_MTB_5{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_81_0 = {54 68 65 20 6e 65 74 77 6f 72 6b 20 69 73 20 4c 4f 43 4b 45 44 } //1 The network is LOCKED
		$a_81_1 = {46 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 77 72 69 74 65 20 48 45 52 45 3a } //1 For decryption tool write HERE:
		$a_81_2 = {49 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 2c 20 77 65 20 77 69 6c 6c 20 70 75 62 6c 69 73 68 20 70 72 69 76 61 74 65 20 64 61 74 61 20 6f 6e 20 6f 75 72 20 6e 65 77 73 20 73 69 74 65 2e } //1 If you do not pay, we will publish private data on our news site.
		$a_81_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}
rule Ransom_Win32_Filecoder_DH_MTB_6{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {48 6f 77 5f 54 6f 5f 44 65 63 72 79 70 74 2e 74 78 74 } //1 How_To_Decrypt.txt
		$a_81_1 = {2e 69 6e 69 2e 65 6e 63 72 79 70 74 65 64 } //1 .ini.encrypted
		$a_81_2 = {57 65 20 63 61 6e 20 67 61 72 61 6e 74 65 65 20 77 68 61 74 20 77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 61 6e 79 20 79 6f 75 72 20 66 69 6c 65 } //1 We can garantee what we can decrypt any your file
		$a_81_3 = {77 65 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 61 6e 64 20 73 68 6f 77 20 73 6f 6d 65 20 70 61 72 74 20 6f 66 20 64 65 63 72 79 70 74 65 64 20 66 69 6c 65 } //1 we will decrypt and show some part of decrypted file
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Filecoder_DH_MTB_7{
	meta:
		description = "Ransom:Win32/Filecoder.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6d 41 52 41 53 55 46 40 63 6f 63 6b 2e 6c 69 } //1 mARASUF@cock.li
		$a_81_1 = {21 49 4e 46 4f 2e 48 54 41 } //1 !INFO.HTA
		$a_81_2 = {73 6f 20 69 66 20 79 6f 75 20 77 61 6e 74 20 79 6f 75 72 20 66 69 6c 65 73 20 64 6f 6e 74 20 62 65 20 73 68 79 20 66 65 65 6c 20 66 72 65 65 20 74 6f 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 64 6f 20 61 6e 20 61 67 72 65 65 6d 65 6e 74 20 6f 6e 20 70 72 69 63 65 } //1 so if you want your files dont be shy feel free to contact us and do an agreement on price
		$a_81_3 = {44 65 6c 65 74 65 20 79 6f 75 20 66 69 6c 65 73 20 69 66 20 79 6f 75 20 64 6f 6e 74 20 6e 65 65 64 20 74 68 65 6d } //1 Delete you files if you dont need them
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}