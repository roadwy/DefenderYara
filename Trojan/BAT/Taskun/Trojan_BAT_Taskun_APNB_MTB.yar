
rule Trojan_BAT_Taskun_APNB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.APNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 05 06 7b ?? 00 00 04 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 17 13 04 12 00 28 ?? 00 00 06 00 2b 78 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 16 fe 01 13 0d 11 0d 2c 02 2b 5d 06 7b ?? 00 00 04 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 18 13 04 12 00 28 ?? 00 00 06 00 2b 3f 06 7b ?? 00 00 04 6f ?? 00 00 0a 03 fe 04 16 fe 01 13 0e 11 0e 2c 02 2b 24 06 7b ?? 00 00 04 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 58 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}