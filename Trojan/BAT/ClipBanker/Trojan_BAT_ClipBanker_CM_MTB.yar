
rule Trojan_BAT_ClipBanker_CM_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {42 65 64 73 2d 50 72 6f 74 65 63 74 6f 72 } //3 Beds-Protector
		$a_81_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //3 set_UseShellExecute
		$a_81_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //3 MD5CryptoServiceProvider
		$a_81_3 = {42 65 64 73 2d 50 72 6f 74 65 63 74 6f 72 2d 54 68 65 2d 51 75 69 63 6b 2d 42 72 6f 77 6e 2d 46 6f 78 2d 4a 75 6d 70 65 64 2d 4f 76 65 72 2d 54 68 65 2d 4c 61 7a 79 2d 44 6f 67 } //3 Beds-Protector-The-Quick-Brown-Fox-Jumped-Over-The-Lazy-Dog
		$a_81_4 = {53 65 63 75 72 69 74 79 48 65 61 6c 74 68 53 65 72 76 69 63 65 } //3 SecurityHealthService
		$a_01_5 = {53 00 54 00 41 00 52 00 54 00 20 00 43 00 4d 00 44 00 20 00 2f 00 43 00 } //3 START CMD /C
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}
rule Trojan_BAT_ClipBanker_CM_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 41 65 73 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //3 System.Security.Cryptography.AesCryptoServiceProvider
		$a_81_1 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 31 30 30 30 39 2d 31 31 31 31 32 7d } //3 {11111-22222-10009-11112}
		$a_81_2 = {6e 6f 53 58 50 46 4d 62 62 5a 68 32 42 61 66 65 6a 34 2e 62 4b 48 44 4c 6f 59 78 32 35 4d 65 55 6f 68 77 72 37 } //3 noSXPFMbbZh2Bafej4.bKHDLoYx25MeUohwr7
		$a_81_3 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 35 30 30 30 31 2d 30 30 30 30 30 7d } //3 {11111-22222-50001-00000}
		$a_81_4 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //3 GetDelegateForFunctionPointer
		$a_81_5 = {72 4a 71 4e 45 65 69 57 58 44 76 4a 73 61 6e 54 62 4c 6a 49 6f 34 48 4f } //3 rJqNEeiWXDvJsanTbLjIo4HO
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}