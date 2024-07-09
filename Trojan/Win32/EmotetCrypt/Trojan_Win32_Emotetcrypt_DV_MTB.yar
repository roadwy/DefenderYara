
rule Trojan_Win32_Emotetcrypt_DV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 08 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 8b 49 ?? 83 c1 0c 51 6a 00 ff d0 } //10
		$a_02_1 = {48 89 44 24 20 3b cf 7e ?? e8 ?? ?? ?? ?? 8b 54 24 54 f2 0f 59 44 24 68 8a 02 42 89 54 24 54 8b 54 24 38 f2 0f 58 44 24 48 88 02 42 8b 44 24 20 f2 0f 11 44 24 48 89 54 24 38 85 c0 74 ?? f2 0f 10 44 24 78 8b 4c 24 1c eb } //10
		$a_81_2 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //10 RaiseException
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_81_4 = {61 73 62 69 71 73 74 61 65 71 7a 73 79 63 63 } //1 asbiqstaeqzsycc
		$a_81_5 = {61 74 77 75 68 6b 79 63 66 79 62 6b 6a } //1 atwuhkycfybkj
		$a_81_6 = {62 64 6b 69 70 79 76 71 } //1 bdkipyvq
		$a_81_7 = {62 67 62 62 79 74 7a 69 6f 6c 6f } //1 bgbbytziolo
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=44
 
}