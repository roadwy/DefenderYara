
rule Trojan_BAT_AgentTesla_EJU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 46 00 67 00 43 00 65 00 77 00 51 00 7e 00 7e 00 7e 00 52 00 59 00 49 00 49 00 30 00 37 00 34 00 48 00 77 00 43 00 65 00 77 00 6b 00 7e 00 7e 00 7e 00 52 00 59 00 59 00 58 00 30 00 48 00 7e 00 7e 00 7e 00 } //01 00  BFgCewQ~~~RYII074HwCewk~~~RYYX0H~~~
		$a_01_1 = {4c 00 6f 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 61 00 64 00 } //01 00  Lo------ad
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 } //00 00 
	condition:
		any of ($a_*)
 
}