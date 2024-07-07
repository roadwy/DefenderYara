
rule Trojan_Win32_Qakbot_PM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 } //1 Wind
		$a_03_1 = {8b 45 fc 0f b6 44 10 90 01 01 33 c8 90 02 04 90 13 8b 45 90 01 01 03 45 90 01 01 88 08 90 13 8b 45 90 01 01 40 90 13 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 73 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}