
rule Trojan_BAT_Clipbanker_KAE_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 fe 0c 04 00 6f ?? 00 00 0a fe 0e 05 00 00 fe 0c 01 00 fe 0c 05 00 fe 0c 00 00 fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 6f ?? 00 00 0a 00 fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 00 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04 00 fe 0c 03 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}