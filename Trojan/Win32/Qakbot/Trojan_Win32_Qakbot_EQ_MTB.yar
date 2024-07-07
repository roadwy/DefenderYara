
rule Trojan_Win32_Qakbot_EQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 48 8b 55 90 01 01 33 02 89 45 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 02 33 c0 89 45 90 01 01 8b 45 90 01 01 83 c0 04 03 45 90 01 01 89 45 90 01 01 6a 00 e8 90 01 04 8b 5d 90 01 01 83 c3 04 03 5d 90 01 01 2b d8 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}