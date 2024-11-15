
rule Trojan_BAT_Zilla_PFFH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PFFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 1f 64 fe 01 2c 07 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 1f 1e fe 01 2c 14 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 1f 14 fe 01 2c 21 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2a 12 03 28 ?? 00 00 0a 20 ff 00 00 00 fe 01 2c 27 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=1
 
}