
rule Trojan_BAT_Exnet_PSED_MTB{
	meta:
		description = "Trojan:BAT/Exnet.PSED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {6f 40 00 00 0a 28 41 90 01 03 03 61 13 04 1d 13 05 00 11 05 17 fe 01 2c 03 18 13 05 00 11 05 20 4f ff ff ff fe 1c 1c 00 00 01 59 7e 08 00 00 04 16 94 58 fe 01 2c 1c 06 17 d6 0a 7e 08 00 00 04 17 94 fe 1c 17 00 00 01 59 7e 08 00 00 04 18 94 59 13 05 00 11 05 1f 8e fe 1c 1a 00 00 01 59 7e 08 00 00 04 19 94 58 fe 01 2c 1a 06 07 31 8f 20 60 fe ff ff fe 1c 17 00 00 01 59 7e 08 00 00 04 1a 94 58 13 05 00 11 05 1b fe 01 2c 05 2b dc 1c 13 05 00 11 05 19 fe 01 2c 0c 02 6f 42 90 01 03 17 da 0b 1a 13 05 00 11 05 1d fe 01 2c 24 08 11 04 28 43 90 01 03 28 44 00 00 0a 90 00 } //5
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}