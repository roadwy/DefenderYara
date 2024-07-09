
rule Trojan_BAT_ArkeiStealer_AAZO_MTB{
	meta:
		description = "Trojan:BAT/ArkeiStealer.AAZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 20 10 7e 02 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 04 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0c de 22 11 05 2c 07 11 05 6f ?? 00 00 0a dc } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}