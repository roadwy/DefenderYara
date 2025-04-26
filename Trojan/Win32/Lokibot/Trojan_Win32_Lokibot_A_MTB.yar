
rule Trojan_Win32_Lokibot_A_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 45 f8 43 81 7d f8 90 0a 30 00 8a 03 34 ?? 88 07 90 05 10 01 90 8a 07 e8 ?? ?? ?? ?? 90 05 10 01 90 83 06 01 73 ?? e8 ?? ?? ?? ?? 90 05 10 01 90 ff 45 f8 43 81 7d f8 ?? ?? ?? ?? 75 ?? 90 05 10 01 90 8b 4d fc 90 05 10 01 90 81 c1 ?? ?? ?? ?? 90 05 10 01 90 ff d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}