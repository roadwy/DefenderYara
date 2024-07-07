
rule Trojan_Win32_Qakbot_GS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af c1 2b 45 90 01 01 66 89 45 90 01 01 0f b6 15 90 01 04 0f af 15 90 01 04 2b 15 90 01 04 88 15 90 01 04 0f b7 45 90 01 01 83 c0 90 01 01 2b 45 90 01 01 66 89 45 90 01 01 8b 75 90 01 01 81 c2 90 01 04 42 ff e6 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GS_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 a3 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 09 2d 00 03 05 90 01 04 8b 15 90 01 04 33 02 a3 90 02 0f 03 05 90 01 04 8b 15 90 01 04 89 02 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}