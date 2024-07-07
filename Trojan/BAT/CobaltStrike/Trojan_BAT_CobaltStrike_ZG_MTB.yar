
rule Trojan_BAT_CobaltStrike_ZG_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.ZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 28 13 00 00 0a 03 6f 90 01 03 0a 0a 7e 90 01 03 04 0b 02 28 90 01 03 0a 0c 73 90 01 03 0a 0d 73 90 01 03 0a 13 04 11 04 09 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 13 05 11 05 08 16 08 8e 69 6f 90 01 03 0a 00 11 05 6f 90 01 03 0a 00 28 90 01 03 0a 11 04 6f 90 01 03 0a 6f 90 01 03 0a 13 06 dd 90 01 03 00 90 00 } //1
		$a_01_1 = {45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 EncryptionKey
		$a_01_2 = {52 75 6e 53 63 72 69 70 74 } //1 RunScript
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}