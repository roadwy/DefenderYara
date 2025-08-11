
rule Trojan_BAT_Taskun_ZXW_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0b 02 11 0a 11 0b 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 19 fe 04 16 fe 01 13 0e 11 0e 2c 55 00 16 13 0f 11 0f 17 5f 17 fe 01 16 fe 01 13 10 11 10 2c 2e 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 0d 00 06 1e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}