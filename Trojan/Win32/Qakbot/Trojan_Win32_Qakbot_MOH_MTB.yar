
rule Trojan_Win32_Qakbot_MOH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c6 04 8b 82 90 01 04 31 42 90 01 01 b8 90 01 04 2b 82 90 01 04 01 82 90 01 04 8b 42 90 01 01 2d 90 01 04 01 42 90 01 01 8b 82 90 01 04 01 42 90 01 01 b8 90 01 04 2b 42 90 01 01 01 82 90 01 04 8b 42 90 01 01 33 82 90 01 04 35 90 01 04 89 42 90 01 01 81 fe 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}