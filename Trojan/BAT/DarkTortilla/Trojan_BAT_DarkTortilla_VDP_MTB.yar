
rule Trojan_BAT_DarkTortilla_VDP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.VDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 03 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 07 03 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 07 07 6f ?? 01 00 0a 07 6f ?? 01 00 0a 6f ?? 01 00 0a 0c 00 73 86 01 00 0a 0d 00 09 08 17 73 87 01 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 01 00 0a 00 11 05 6f ?? 01 00 0a 00 de 0e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}