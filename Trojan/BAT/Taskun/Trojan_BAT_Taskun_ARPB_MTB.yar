
rule Trojan_BAT_Taskun_ARPB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 11 08 6f ?? ?? 00 0a 13 0b 12 0b 28 ?? ?? 00 0a 13 0c 12 0b 28 ?? ?? 00 0a 13 0d 12 0b 28 ?? ?? 00 0a 13 0e 11 0c 09 28 ?? 00 00 06 13 0c 11 0d 09 17 58 28 ?? 00 00 06 13 0d 11 0e 09 18 58 28 ?? 00 00 06 13 0e 11 05 2c 21 11 05 11 0c 6f ?? 00 00 06 13 0c 11 05 11 0d 6f ?? 00 00 06 13 0d 11 05 11 0e 6f ?? 00 00 06 13 0e 11 0c 20 ab 00 00 00 58 20 ff 00 00 00 5f d2 13 0c 11 0c 20 ab 00 00 00 59 20 ff 00 00 00 5f d2 13 0c 11 0d 1c 62 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}