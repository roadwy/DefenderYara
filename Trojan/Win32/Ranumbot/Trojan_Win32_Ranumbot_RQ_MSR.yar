
rule Trojan_Win32_Ranumbot_RQ_MSR{
	meta:
		description = "Trojan:Win32/Ranumbot.RQ!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 04 03 74 24 ?? 8d 14 1f 33 f2 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}