
rule Trojan_BAT_DiscordStealer_MK_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 11 08 58 02 09 11 08 58 91 11 06 11 08 91 61 d2 9c 11 08 17 58 13 08 11 08 11 07 32 e1 } //20
		$a_81_1 = {52 49 56 41 54 4f 52 20 53 54 45 41 4c 45 52 } //15 RIVATOR STEALER
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*15) >=35
 
}