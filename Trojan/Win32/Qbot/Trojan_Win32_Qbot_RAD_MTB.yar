
rule Trojan_Win32_Qbot_RAD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b 15 90 01 04 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 8d 54 01 90 01 01 2b 95 90 01 04 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 83 e8 15 a3 90 01 04 eb 90 01 01 8b 0d 90 01 04 03 8d 90 01 04 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 b8 01 00 00 00 85 c0 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}