
rule Trojan_BAT_Taskun_GSC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 04 03 6f ?? 00 00 0a 59 0d 09 19 32 55 12 ?? 28 ?? 00 00 0a 1f 10 62 12 ?? 28 ?? 00 00 0a 1e 62 60 12 ?? 28 ?? 00 00 0a 60 13 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}