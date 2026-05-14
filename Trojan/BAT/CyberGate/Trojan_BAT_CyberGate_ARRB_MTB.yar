
rule Trojan_BAT_CyberGate_ARRB_MTB{
	meta:
		description = "Trojan:BAT/CyberGate.ARRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 07 11 04 11 07 6f ?? 00 00 0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 11 04 11 07 6f ?? 00 00 0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 11 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0a 00 11 05 28 ?? 00 00 0a 0b 06 07 16 07 8e b7 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 00 28 ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 dd } //5
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}