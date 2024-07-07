
rule VirTool_BAT_Obfuscator_E{
	meta:
		description = "VirTool:BAT/Obfuscator.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 42 72 65 6e 64 61 6e 5c 44 65 73 6b 74 6f 70 5c 43 72 79 70 74 65 72 73 5c 53 69 63 6b 61 6e 64 65 72 73 20 43 72 79 70 74 65 72 20 } //1 C:\Users\Brendan\Desktop\Crypters\Sickanders Crypter 
		$a_01_1 = {5f 43 6f 72 45 78 65 4d 61 69 6e 00 6d 73 63 6f 72 65 65 2e 64 6c 6c 00 } //1
		$a_01_2 = {4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00 } //1 祍灁汰捩瑡潩n
		$a_01_3 = {4d 79 43 6f 6d 70 75 74 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}