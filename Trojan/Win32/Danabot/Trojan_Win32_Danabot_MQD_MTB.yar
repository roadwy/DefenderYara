
rule Trojan_Win32_Danabot_MQD_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 03 f0 8b 84 24 f4 0a 00 00 8a 04 01 88 84 24 33 0b 00 00 8b c2 2b c1 03 05 ?? ?? ?? ?? 3b 84 24 10 0b 00 00 76 ?? 8b 84 24 d0 0a 00 00 03 05 ?? ?? ?? ?? 89 84 24 d0 0a 00 00 8b 84 24 14 0b 00 00 30 84 24 33 0b 00 00 3b c2 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}