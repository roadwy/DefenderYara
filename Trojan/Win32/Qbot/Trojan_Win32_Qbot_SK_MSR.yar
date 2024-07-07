
rule Trojan_Win32_Qbot_SK_MSR{
	meta:
		description = "Trojan:Win32/Qbot.SK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 a1 90 01 03 00 8b d2 8b 0d 90 01 03 00 8b d2 a3 90 01 03 00 8b c0 a1 90 01 03 00 a3 90 01 03 00 a1 90 01 03 00 8b d8 a1 90 01 03 00 33 d9 c7 05 90 01 03 00 90 01 03 00 01 1d 90 01 03 00 a1 90 01 03 00 8b 0d 90 01 03 00 89 08 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}