
rule Trojan_Win64_Emotetcrypt_FN_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_81_0 = {66 73 6d 61 73 6c 79 78 6f 70 74 6f 75 79 72 63 6e 67 76 70 68 2e 64 6c 6c } //10 fsmaslyxoptouyrcngvph.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //1 RaiseException
		$a_81_5 = {61 66 65 6c 77 66 7a 72 79 70 72 76 63 72 76 } //1 afelwfzryprvcrv
		$a_81_6 = {61 6e 61 75 78 65 61 62 72 6d 75 69 76 65 } //1 anauxeabrmuive
		$a_81_7 = {63 6c 7a 72 66 75 76 65 6d 6e 69 71 65 66 63 6f } //1 clzrfuvemniqefco
		$a_81_8 = {66 79 76 6a 62 79 74 64 6c 70 71 78 6e 67 75 } //1 fyvjbytdlpqxngu
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=18
 
}