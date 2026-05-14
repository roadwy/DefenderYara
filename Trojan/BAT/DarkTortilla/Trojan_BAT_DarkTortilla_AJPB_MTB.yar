
rule Trojan_BAT_DarkTortilla_AJPB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AJPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 16 fe 01 0d 09 2c 05 38 ?? ?? 00 00 7e ?? ?? 00 04 2c 07 7e ?? ?? 00 04 2b 16 7e ?? ?? 00 04 fe ?? ?? ?? 00 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 0a 20 ac 00 00 00 0b 16 0c 2b 0f 06 02 07 08 6f ?? ?? 00 0a 00 08 1e d6 0c 00 08 02 8e 69 fe 04 13 04 11 04 2d e5 } //4
		$a_01_1 = {03 05 03 05 91 04 61 9c 2a } //5
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*5) >=9
 
}