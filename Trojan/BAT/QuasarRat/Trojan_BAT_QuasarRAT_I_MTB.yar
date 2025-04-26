
rule Trojan_BAT_QuasarRAT_I_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 ff b6 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9e 00 00 00 5e 04 00 00 4e 01 00 00 d7 13 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}