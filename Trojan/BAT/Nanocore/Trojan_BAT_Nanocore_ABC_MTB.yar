
rule Trojan_BAT_Nanocore_ABC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 b7 b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 fa 00 00 00 4c 00 00 00 c1 00 00 00 } //2
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_3 = {43 6c 69 70 62 6f 61 72 64 } //1 Clipboard
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 42 6c 6f 63 6b } //1 TransformBlock
		$a_01_6 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_7 = {52 00 53 00 35 00 35 00 51 00 37 00 34 00 44 00 37 00 48 00 37 00 47 00 48 00 } //1 RS55Q74D7H7GH
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}