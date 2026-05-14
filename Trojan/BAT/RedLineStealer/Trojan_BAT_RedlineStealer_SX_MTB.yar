
rule Trojan_BAT_RedlineStealer_SX_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 ?? ?? ?? ?? ?? fe 0c 01 00 58 20 ff 00 00 00 5f 61 d1 9d fe 0c 01 00 17 58 fe 0e 01 00 fe 0c 01 00 fe 0c 00 00 8e 69 32 c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}