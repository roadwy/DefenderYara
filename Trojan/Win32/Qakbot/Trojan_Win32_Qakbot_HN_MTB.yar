
rule Trojan_Win32_Qakbot_HN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 10 90 01 01 3a ff 74 90 01 01 03 45 90 01 01 88 08 e9 90 01 04 e9 90 01 04 5e f7 f6 66 3b c9 74 90 01 01 83 c3 90 01 01 53 66 3b c9 74 90 01 01 21 5d 90 01 01 8d 45 90 01 01 eb 90 01 01 53 58 3a e4 74 90 01 01 c1 e0 90 01 01 8b 44 05 90 01 01 3a ed 74 90 01 01 33 c8 8b 45 90 01 01 66 3b c9 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}