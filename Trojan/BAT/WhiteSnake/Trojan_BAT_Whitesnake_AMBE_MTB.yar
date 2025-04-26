
rule Trojan_BAT_Whitesnake_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Whitesnake.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 fe 0c 06 00 fe 09 00 00 fe 0c 06 00 6f ?? 00 00 0a fe 0c 02 00 fe 0c 06 00 fe 0c 02 00 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 9d fe 0c 06 00 20 01 00 00 00 58 fe 0e 06 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}