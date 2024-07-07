
rule Ransom_Win32_TimeCrypt_MAK_MTB{
	meta:
		description = "Ransom:Win32/TimeCrypt.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 69 6d 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Time Ransomware
		$a_81_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 6d 75 73 69 63 73 2c 76 69 64 65 6f 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //2 All of your documents,musics,videos have been encrypted
		$a_81_2 = {54 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 64 61 74 61 2c 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 75 73 } //2 To recover your data, you need to pay us
		$a_81_3 = {77 65 20 77 69 6c 6c 20 6c 65 61 6b 20 65 76 65 72 79 74 68 69 6e 67 20 6f 6e 20 74 68 65 20 64 61 72 6b 20 77 65 62 } //2 we will leak everything on the dark web
		$a_81_4 = {64 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //2 do not rename encrypted files
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=7
 
}