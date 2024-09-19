
rule Trojan_BAT_PureLogs_KAF_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 95 61 28 ?? 00 00 0a 9c fe 0c 06 00 20 ?? 00 00 00 6a 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}