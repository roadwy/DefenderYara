
rule Trojan_Win32_Qakbot_HH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 90 09 2f 00 89 18 a1 90 01 04 03 05 90 01 04 a3 90 01 04 6a 00 e8 90 01 04 8b d8 03 1d 90 01 04 6a 00 e8 90 01 04 03 d8 a1 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}