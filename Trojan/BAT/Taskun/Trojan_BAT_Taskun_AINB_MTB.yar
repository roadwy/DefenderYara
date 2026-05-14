
rule Trojan_BAT_Taskun_AINB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AINB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 05 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 17 13 04 2b 35 11 04 17 fe 01 13 0e 11 0e 2c 14 00 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 18 13 04 2b 16 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 58 0d 16 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}