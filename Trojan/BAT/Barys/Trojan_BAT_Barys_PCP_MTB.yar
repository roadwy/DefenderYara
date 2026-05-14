
rule Trojan_BAT_Barys_PCP_MTB{
	meta:
		description = "Trojan:BAT/Barys.PCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 12 6f ?? 00 00 0a 17 73 08 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 20 06 00 00 00 7e 21 00 00 04 7b 75 00 00 04 3a 1d 00 00 00 26 20 00 00 00 00 38 12 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0c 00 fe 0c 0c 00 45 01 00 00 00 26 00 00 00 fe 0c 0c 00 20 dc 03 00 00 3b e5 ff ff ff 38 13 00 00 00 11 01 6f ?? 00 00 0a 73 0b 00 00 0a 13 09 38 0c 00 00 00 11 02 6f ?? 00 00 0a 38 e1 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}