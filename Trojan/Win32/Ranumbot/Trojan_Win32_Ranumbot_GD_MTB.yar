
rule Trojan_Win32_Ranumbot_GD_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 ce c1 ee 90 01 01 89 74 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 94 24 90 01 04 8d 34 17 33 f1 81 3d 90 01 08 c7 05 90 01 08 90 18 31 74 24 90 01 01 81 3d 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}