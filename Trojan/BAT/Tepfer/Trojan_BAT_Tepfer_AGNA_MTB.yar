
rule Trojan_BAT_Tepfer_AGNA_MTB{
	meta:
		description = "Trojan:BAT/Tepfer.AGNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 1f 0c 5d 09 1f 2c 5d 58 20 8d 03 00 00 09 1f 23 5d 20 d3 00 00 00 58 5a 58 13 04 06 09 6f ?? 00 00 0a 11 04 59 d1 13 05 07 11 05 6f ?? 00 00 0a 26 09 17 58 0d 09 06 6f ?? 00 00 0a 32 c1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}