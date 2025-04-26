
rule Trojan_Win32_Qakbot_PM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 } //1 Wind
		$a_03_1 = {8b 45 fc 0f b6 44 10 ?? 33 c8 [0-04] 90 13 8b 45 ?? 03 45 ?? 88 08 90 13 8b 45 ?? 40 90 13 89 45 ?? 8b 45 ?? 3b 45 ?? 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}