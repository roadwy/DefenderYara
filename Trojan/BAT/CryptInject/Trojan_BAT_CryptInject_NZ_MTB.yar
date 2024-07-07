
rule Trojan_BAT_CryptInject_NZ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 34 32 38 31 62 32 30 38 2d 33 39 61 35 2d 34 63 63 34 2d 62 35 32 34 2d 36 65 39 61 66 36 32 36 66 36 32 31 } //10 $4281b208-39a5-4cc4-b524-6e9af626f621
		$a_01_1 = {4d 61 6c 61 67 61 5f 67 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //10 Malaga_game.Properties.Resource
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_4 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}