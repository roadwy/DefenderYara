
rule Trojan_BAT_AgentTesla_NMP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {07 16 fe 02 16 fe 01 0c 08 2c 1c 07 17 d6 0b 06 72 e9 08 00 70 28 bf 00 00 0a 8c 82 00 00 01 6f c0 00 00 0a 00 2b d8 } //10
		$a_01_1 = {07 16 fe 02 16 fe 01 0c 08 2c 1c 07 17 d6 0b 06 72 e9 08 00 70 28 bf 00 00 0a 8c 3c 00 00 01 6f c0 00 00 0a 00 2b d8 } //10
		$a_01_2 = {07 16 fe 02 16 fe 01 0c 08 2c 1c 07 17 d6 0b 06 72 04 3d 00 70 28 73 01 00 0a 8c 66 00 00 01 6f c8 00 00 0a 00 2b d8 } //10
		$a_01_3 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}