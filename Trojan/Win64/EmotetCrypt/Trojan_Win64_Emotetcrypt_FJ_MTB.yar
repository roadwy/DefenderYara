
rule Trojan_Win64_Emotetcrypt_FJ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_81_0 = {6d 7a 6f 6e 75 64 74 2e 64 6c 6c } //10 mzonudt.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //1 RaiseException
		$a_81_5 = {62 66 66 6d 6a 74 6d 6d 73 76 73 64 77 6e 74 } //1 bffmjtmmsvsdwnt
		$a_81_6 = {63 6b 69 61 72 6d 61 69 64 75 65 6f 6d 6d 79 6e } //1 ckiarmaidueommyn
		$a_81_7 = {64 76 67 66 62 76 7a 6e 75 70 79 7a 62 65 6e } //1 dvgfbvznupyzben
		$a_81_8 = {65 71 6b 7a 6e 6f 71 6d 7a 76 61 6c 71 73 72 66 } //1 eqkznoqmzvalqsrf
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=18
 
}