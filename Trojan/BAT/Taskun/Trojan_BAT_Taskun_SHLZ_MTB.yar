
rule Trojan_BAT_Taskun_SHLZ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SHLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 06 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 06 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}