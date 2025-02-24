
rule Trojan_BAT_Taskun_SYDF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SYDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 19 2f 02 2b 51 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0a 02 06 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 02 06 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 02 06 20 ff 00 00 00 5f d2 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}