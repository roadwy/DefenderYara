
rule Trojan_BAT_MSILZilla_GKN_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 03 00 3b 30 00 00 00 fe 0c 09 00 fe 0c 05 00 46 fe 0c 13 00 61 52 fe 0c 05 00 20 01 00 00 00 58 fe 0e 05 00 fe 0c 09 00 20 01 00 00 00 58 fe 0e 09 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}