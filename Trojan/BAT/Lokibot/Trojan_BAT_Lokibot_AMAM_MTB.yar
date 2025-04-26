
rule Trojan_BAT_Lokibot_AMAM_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AMAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 95 d2 13 [0-0a] 61 [0-0f] 20 ff 00 00 00 5f d2 9c 00 11 ?? 17 6a 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}