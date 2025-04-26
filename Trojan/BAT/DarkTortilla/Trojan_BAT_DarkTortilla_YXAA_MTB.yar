
rule Trojan_BAT_DarkTortilla_YXAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.YXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 2c 11 04 1c 5d 16 fe 01 13 05 11 05 2c 0f 08 11 04 07 11 04 91 1f 3f 61 b4 9c 00 2b 0a 00 08 11 04 07 11 04 91 9c 00 11 04 17 d6 13 04 11 04 09 31 cf } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}