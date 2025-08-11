
rule Trojan_BAT_Tedy_PGTK_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PGTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 04 6f ?? 00 00 0a 80 02 00 00 04 20 02 00 00 00 fe 0e 04 00 00 fe 0c 04 00 20 03 00 00 00 fe 01 39 2b 00 00 00 28 ?? 00 00 0a 20 0a 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}