
rule Trojan_BAT_Crysan_KLS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.KLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {d0 21 00 00 01 28 ?? ?? ?? 0a 72 01 00 00 70 17 8d 14 00 00 01 25 16 d0 21 00 00 01 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 14 17 8d 10 00 00 01 25 16 02 50 a2 6f ?? ?? ?? 0a 26 2a } //4
		$a_81_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //2 GetExportedTypes
		$a_81_2 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //2 GetAssemblies
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 73 } //2 GetMethods
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=10
 
}