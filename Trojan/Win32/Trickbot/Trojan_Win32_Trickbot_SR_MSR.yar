
rule Trojan_Win32_Trickbot_SR_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.SR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 15 48 d8 4b 00 03 15 d0 cd 4b 00 0f b6 02 8b 4d fc 0f b6 11 03 d0 8b 45 fc 88 10 } //1
		$a_02_1 = {8b 55 fc 03 15 90 01 04 8b 45 08 03 10 8b 4d 08 89 11 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}