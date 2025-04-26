
rule Trojan_BAT_Snakekeylogger_SHLH_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.SHLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}