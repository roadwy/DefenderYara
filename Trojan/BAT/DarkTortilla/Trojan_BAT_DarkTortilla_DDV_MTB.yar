
rule Trojan_BAT_DarkTortilla_DDV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.DDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 16 11 07 11 06 18 28 ?? 00 00 06 28 ?? 00 00 0a 13 08 16 16 02 74 09 00 00 1b 08 91 11 08 28 ?? 00 00 0a 18 28 ?? 00 00 06 28 ?? 00 00 0a 13 09 1d 13 0c 38 a7 fe ff ff 07 75 0b 00 00 1b 1a 9a 74 09 00 00 1b 08 11 09 28 ?? 00 00 0a 9c 08 17 d6 0c 1c 13 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}