
rule Trojan_Win32_Emotetcrypt_EF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {65 61 6f 6e 70 68 6c 69 74 68 79 6e 2e 64 6c 6c } //1 eaonphlithyn.dll
		$a_81_2 = {61 75 6b 6a 62 7a 64 6c 6f 71 71 72 66 76 } //1 aukjbzdloqqrfv
		$a_81_3 = {61 75 78 69 67 75 67 6d 66 74 6e 78 6f } //1 auxigugmftnxo
		$a_81_4 = {63 6b 79 77 65 67 6d 74 6b 76 74 63 73 6e } //1 ckywegmtkvtcsn
		$a_81_5 = {65 71 71 75 64 71 6b 64 76 71 6a 62 78 76 70 77 6d } //1 eqqudqkdvqjbxvpwm
		$a_81_6 = {6b 71 76 6b 62 70 68 73 6c 7a 78 71 67 2e 64 6c 6c } //1 kqvkbphslzxqg.dll
		$a_81_7 = {65 6e 75 62 71 68 79 68 72 64 72 61 76 61 6b } //1 enubqhyhrdravak
		$a_81_8 = {6b 6a 6f 6a 68 6b 69 74 74 70 6f 7a 71 70 64 } //1 kjojhkittpozqpd
		$a_81_9 = {6c 6d 74 72 77 6c 70 77 71 74 6a 68 76 74 75 6a } //1 lmtrwlpwqtjhvtuj
		$a_81_10 = {6d 61 63 74 74 76 67 68 62 67 78 72 6f 65 73 67 } //1 macttvghbgxroesg
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=15
 
}