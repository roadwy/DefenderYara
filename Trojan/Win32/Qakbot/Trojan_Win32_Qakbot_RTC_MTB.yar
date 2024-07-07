
rule Trojan_Win32_Qakbot_RTC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 89 1d 90 01 04 a1 90 01 04 3b 05 90 01 04 0f 82 90 01 04 c7 05 90 01 05 bb 00 00 a1 90 01 04 03 05 90 01 04 a3 90 01 04 83 05 90 01 04 04 81 2d 90 01 04 00 10 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}