
rule Trojan_BAT_AmsiBypass_CCHT_MTB{
	meta:
		description = "Trojan:BAT/AmsiBypass.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 08 6f ?? 00 00 0a 11 19 91 11 0a 11 19 11 0a 8e 69 5d 91 61 d2 6f ?? 00 00 0a 11 19 17 58 13 19 11 19 6a 11 08 6f ?? 00 00 0a 32 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}