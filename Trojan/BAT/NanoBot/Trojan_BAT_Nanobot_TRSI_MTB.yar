
rule Trojan_BAT_Nanobot_TRSI_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.TRSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 16 09 16 1f 10 28 ?? ?? ?? 0a 11 04 16 09 1f 0f 1f 10 28 ?? ?? ?? 0a 06 09 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c 08 02 16 02 8e b7 6f ?? ?? ?? 0a 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}