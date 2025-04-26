
rule Trojan_BAT_Zilla_KAJ_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 09 00 00 fe 0c 02 00 fe 0c 01 00 6f ?? 00 00 0a fe 0e 03 00 fe 0c 00 00 fe 0c 02 00 fe 0c 01 00 fe 0c 03 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}