
rule Trojan_Win32_Ranumbot_GM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c6 33 c8 8d 90 01 01 24 90 01 04 89 90 01 01 24 90 01 01 e8 90 01 04 81 90 01 05 83 90 01 01 01 90 0a 50 00 8b 90 01 01 c1 90 01 01 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 02 00 00 01 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 01 8b 90 01 01 24 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}