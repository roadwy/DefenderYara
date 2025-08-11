
rule Trojan_BAT_VIPKeylogger_ZZV_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ZZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 59 03 6f ?? 01 00 0a 6f ?? 01 00 0a 20 00 01 00 00 5d 03 6f ?? 01 00 0a 6f ?? 01 00 0a 20 00 01 00 00 5d 61 d2 03 6f ?? 01 00 0a 6f ?? 01 00 0a 1f 1f 5a 03 6f ?? 01 00 0a 6f ?? 01 00 0a 58 20 ff 00 00 00 5f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}