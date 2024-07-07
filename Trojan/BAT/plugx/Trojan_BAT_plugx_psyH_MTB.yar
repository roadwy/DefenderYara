
rule Trojan_BAT_plugx_psyH_MTB{
	meta:
		description = "Trojan:BAT/plugx.psyH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 fe 06 02 00 00 06 73 02 00 00 0a 28 03 00 00 06 7e 01 00 00 04 2c 0c 7e 01 00 00 04 14 14 6f 03 00 00 0a 2a } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}