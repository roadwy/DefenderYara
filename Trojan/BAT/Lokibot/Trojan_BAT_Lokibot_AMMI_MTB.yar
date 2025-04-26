
rule Trojan_BAT_Lokibot_AMMI_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AMMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 07 06 91 11 ?? 61 13 ?? 07 06 17 58 07 8e 69 5d 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}