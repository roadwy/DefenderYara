
rule Trojan_Win32_Ranumbot_MX_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 6c 24 58 b3 30 c7 6b 81 84 24 40 02 00 00 21 f4 7c 36 8b 44 24 ?? 30 0c 06 b8 01 00 00 00 29 44 24 ?? 83 7c 24 04 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}