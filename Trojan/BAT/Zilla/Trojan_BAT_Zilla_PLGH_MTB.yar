
rule Trojan_BAT_Zilla_PLGH_MTB{
	meta:
		description = "Trojan:BAT/Zilla.PLGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 2d 11 08 07 1f 10 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2b 0f 08 07 1f 10 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc 11 04 6f ?? 00 00 0a 13 07 de 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}