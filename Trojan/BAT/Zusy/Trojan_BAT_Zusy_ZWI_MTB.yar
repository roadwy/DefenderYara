
rule Trojan_BAT_Zusy_ZWI_MTB{
	meta:
		description = "Trojan:BAT/Zusy.ZWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 08 00 fe 0c 0e 00 fe 0c 0f 00 6f ?? 00 00 0a fe 0e 10 00 fe 0c 0c 00 fe 0c 0d 00 25 28 ?? 05 00 06 58 fe 0e 0d 00 fe 0d 10 00 28 ?? 00 00 0a 9c fe 0c 0d 00 fe 0c 0b 00 fe 04 28 ?? 03 00 06 fe 01 fe 0e 1d 00 fe 0c 1d 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}