
rule Trojan_BAT_Remcos_ZZC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 09 07 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 1f 32 2f 18 12 04 28 ?? 00 00 0a 1f 32 2f 0d 12 04 28 ?? 00 00 0a 1f 64 fe 02 2b 01 16 13 05 11 05 2c 14 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}