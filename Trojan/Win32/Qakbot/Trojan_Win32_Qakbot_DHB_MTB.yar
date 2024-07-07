
rule Trojan_Win32_Qakbot_DHB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 d7 f7 d3 89 44 24 90 01 01 8b 44 24 90 01 01 0f b6 14 10 01 f2 88 d0 0f b6 d0 89 5c 24 90 01 01 89 7c 24 90 01 01 8b 74 24 90 01 01 8b 7c 24 90 01 01 8a 04 3e 8b 5c 24 90 01 01 32 04 13 8b 54 24 90 01 01 88 04 3a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}