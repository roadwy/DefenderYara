
rule Trojan_BAT_DarkTortilla_BTT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.BTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 13 0c 11 0c 45 07 00 00 00 31 00 00 00 25 00 00 00 00 00 00 00 42 00 00 00 3d 00 00 00 00 00 00 00 31 00 00 00 07 74 8a 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 07 74 8a 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 17 13 0c 2b b8 07 74 8a 00 00 01 19 6f ?? 00 00 0a 07 74 8a 00 00 01 03 6f ?? 00 00 0a 19 13 0c 2b 9b 07 75 8a 00 00 01 03 6f ?? 00 00 0a 07 75 8a 00 00 01 6f 92 00 00 0a 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}