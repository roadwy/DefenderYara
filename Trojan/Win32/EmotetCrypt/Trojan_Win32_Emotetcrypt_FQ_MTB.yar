
rule Trojan_Win32_Emotetcrypt_FQ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_1 = {66 74 6f 6f 71 61 62 6c 78 6a 74 6d 2e 64 6c 6c } //1 ftooqablxjtm.dll
		$a_81_2 = {6a 6f 68 73 6c 79 6d 6d 69 79 62 67 61 6d 67 61 78 } //1 johslymmiybgamgax
		$a_81_3 = {6b 6b 61 73 76 74 69 6e 6f 6b 6f 68 74 78 62 67 } //1 kkasvtinokohtxbg
		$a_81_4 = {6c 61 6d 74 77 64 65 78 78 62 73 6b 7a 78 64 72 } //1 lamtwdexxbskzxdr
		$a_81_5 = {6e 6a 61 61 6c 69 79 6a 73 79 72 6b 70 6e 6c } //1 njaaliyjsyrkpnl
		$a_81_6 = {6d 6f 62 39 6e 36 69 7a 71 38 2e 64 6c 6c } //1 mob9n6izq8.dll
		$a_81_7 = {6c 30 37 67 6f 35 30 71 66 34 6f 72 77 68 35 79 74 75 7a } //1 l07go50qf4orwh5ytuz
		$a_81_8 = {6f 75 31 71 71 37 38 37 63 65 6a 6f 64 74 6c 33 62 72 38 6d 73 64 73 69 } //1 ou1qq787cejodtl3br8msdsi
		$a_81_9 = {7a 7a 31 62 77 37 34 77 62 70 6a 6d 68 31 69 67 36 63 71 39 69 39 6a 6b 6c 6c 66 } //1 zz1bw74wbpjmh1ig6cq9i9jkllf
		$a_81_10 = {6c 37 72 64 36 } //1 l7rd6
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=15
 
}