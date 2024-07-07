
rule Trojan_Win32_Qakbot_DM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 e8 90 01 04 8b d8 8b 45 90 01 01 83 c0 90 01 01 03 d8 e8 90 01 04 2b d8 e8 90 01 04 03 d8 e8 90 01 04 2b d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}