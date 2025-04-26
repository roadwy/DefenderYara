
rule Trojan_BAT_AsyncRAT_SDID_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SDID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0f 00 28 ?? 00 00 0a 1a 5d 0f 00 28 ?? 00 00 0a 9c 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 28 ?? 00 00 06 0b 07 28 ?? 00 00 06 0c 2b 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}