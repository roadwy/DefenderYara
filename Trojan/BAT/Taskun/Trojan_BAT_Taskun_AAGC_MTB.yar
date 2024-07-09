
rule Trojan_BAT_Taskun_AAGC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AAGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 34 00 11 04 11 06 07 11 06 91 09 61 08 11 05 91 61 28 ?? 00 00 0a 9c 11 05 1f 15 fe 01 13 08 11 08 2c 05 16 13 05 2b 06 11 05 17 58 13 05 11 06 17 58 13 06 00 11 06 07 8e 69 17 59 fe 02 16 fe 01 13 09 11 09 2d ba } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}