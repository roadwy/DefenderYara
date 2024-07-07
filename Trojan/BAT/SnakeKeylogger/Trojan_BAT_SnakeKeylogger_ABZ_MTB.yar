
rule Trojan_BAT_SnakeKeylogger_ABZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 bf a2 3d 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 b8 00 00 00 44 00 00 00 1a 01 00 00 ce 02 00 00 18 02 00 00 } //6
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}