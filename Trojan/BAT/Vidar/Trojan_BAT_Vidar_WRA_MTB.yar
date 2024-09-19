
rule Trojan_BAT_Vidar_WRA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.WRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 1c 7e 03 00 00 04 11 1c 6f ?? ?? ?? ?? 7e 03 00 00 04 11 13 6f ?? ?? ?? ?? 03 7e 03 00 00 04 17 6f ?? ?? ?? ?? 8f 14 00 00 01 25 71 14 00 00 01 06 7e 03 00 00 04 16 6f 1a 00 00 0a 91 61 d2 81 14 00 00 01 28 1b 00 00 0a 7e 03 00 00 04 6f 1c 00 00 0a 11 13 17 58 13 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}