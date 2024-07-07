
rule Trojan_BAT_Redline_NEAV_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 07 6f 27 00 00 0a 03 07 03 6f 4d 00 00 0a 5d 6f 27 00 00 0a 61 0c 06 72 41 09 00 70 08 28 3a 01 00 0a 6f 3b 01 00 0a 26 07 17 58 0b 07 02 6f 4d 00 00 0a 32 ca 06 } //10
		$a_01_1 = {53 00 45 00 4c 00 45 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 43 00 54 00 20 00 2a 00 20 00 46 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 52 00 4f 00 4d 00 20 00 57 00 69 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 61 00 74 00 69 00 6e 00 67 00 53 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 79 00 73 00 74 00 65 00 6d 00 } //5 SELEMemoryCT * FMemoryROM WiMemoryn32_OperMemoryatingSMemoryystem
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}