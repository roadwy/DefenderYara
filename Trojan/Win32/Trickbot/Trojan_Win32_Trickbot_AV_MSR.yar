
rule Trojan_Win32_Trickbot_AV_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.AV!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 18 0f b6 04 0f 0f b6 d2 03 c2 33 d2 f7 35 90 01 04 8a 04 0a 8b 54 24 1c 32 04 13 8b 54 24 2c 88 04 13 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}