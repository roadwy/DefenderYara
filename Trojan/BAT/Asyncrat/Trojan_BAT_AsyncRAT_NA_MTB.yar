
rule Trojan_BAT_AsyncRAT_NA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 11 0d 16 11 0b 6f ?? 00 00 0a 25 26 26 11 0a 11 0d 16 11 0b 11 0c 16 6f ?? 00 00 0a 13 0f 7e ?? 00 00 04 11 0c 16 11 0f 6f ?? 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f ?? 00 00 0a 25 26 32 bb } //5
		$a_01_1 = {48 59 59 48 4a 49 4f 70 4c 4b 6d } //1 HYYHJIOpLKm
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}