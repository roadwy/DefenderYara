
rule Trojan_Win32_Ranumbot_GI_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d6 33 ca 8d 84 24 90 01 04 e8 90 0a 64 00 8b 90 01 01 c1 90 01 01 05 c7 05 90 01 08 c7 05 90 01 04 ff ff ff ff 89 90 01 01 24 10 8b 90 01 01 24 90 01 04 01 90 01 01 24 10 81 3d 90 01 08 90 18 8b 90 01 01 24 10 8b 90 01 01 24 0c 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}