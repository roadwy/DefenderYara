
rule Trojan_BAT_Androm_AKTA_MTB{
	meta:
		description = "Trojan:BAT/Androm.AKTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 1a 3c 07 00 00 00 16 0b dd 70 00 00 00 72 ?? ?? 00 70 28 ?? 00 00 0a 0c 72 ?? ?? 00 70 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 03 72 ?? ?? 00 70 11 05 06 16 06 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 dd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}