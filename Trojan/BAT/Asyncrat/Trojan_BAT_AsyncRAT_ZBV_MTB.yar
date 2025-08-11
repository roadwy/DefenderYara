
rule Trojan_BAT_AsyncRAT_ZBV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ZBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 00 09 18 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 05 16 05 8e 69 6f ?? 00 00 0a 13 05 09 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}