
rule Trojan_BAT_Snakekeylogger_SHCK_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.SHCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 03 19 8d 4e 00 00 01 25 16 11 09 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 09 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 09 20 ff 00 00 00 5f d2 9c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}