
rule Trojan_BAT_Exnet_MKV_MTB{
	meta:
		description = "Trojan:BAT/Exnet.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 6f 21 00 00 0a 02 8e 69 07 8e 69 59 8d 18 00 00 01 0c 02 07 8e 69 08 16 08 8e 69 28 ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 08 73 24 00 00 0a 0d 09 06 6f ?? 00 00 0a 16 73 26 00 00 0a 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}