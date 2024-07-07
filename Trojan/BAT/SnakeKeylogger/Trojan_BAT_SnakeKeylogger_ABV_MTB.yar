
rule Trojan_BAT_SnakeKeylogger_ABV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 b7 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b9 00 00 00 38 00 00 00 09 01 00 00 b7 02 00 00 db 01 00 00 } //5
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_5 = {56 65 72 73 69 6f 6e 69 6e 67 48 65 6c 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 VersioningHel.g.resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}