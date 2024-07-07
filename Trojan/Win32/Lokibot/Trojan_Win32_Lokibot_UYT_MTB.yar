
rule Trojan_Win32_Lokibot_UYT_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.UYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 50 4f 33 32 34 45 6d } //1 PPO324Em
	condition:
		((#a_01_0  & 1)*1) >=1
 
}