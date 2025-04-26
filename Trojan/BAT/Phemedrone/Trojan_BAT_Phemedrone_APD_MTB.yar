
rule Trojan_BAT_Phemedrone_APD_MTB{
	meta:
		description = "Trojan:BAT/Phemedrone.APD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 7e 44 01 00 04 6f ?? 00 00 0a 5d 6f ?? 01 00 0a fe 0e 03 00 fe 0c 03 00 61 d1 fe 0e 04 00 fe 0c 01 00 fe 0c 04 00 6f ?? 01 00 0a 26 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 00 00 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}