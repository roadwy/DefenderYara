
rule Trojan_Win32_Qakbot_HG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 05 90 01 01 8b 45 90 01 01 33 d2 66 3b ff 74 90 01 01 bb 90 01 04 53 5e 66 3b f6 74 90 01 01 8b 4d 90 01 01 03 48 90 01 01 89 4d 90 01 01 66 3b d2 74 90 01 01 f7 f6 0f b6 44 15 90 01 01 33 c8 e9 90 01 04 ff 75 90 01 01 8b 45 90 01 01 ff 70 90 01 01 3a f6 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}