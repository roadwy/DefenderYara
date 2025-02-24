
rule Trojan_Win32_Trickbot_MKV_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 c8 8b 4d f0 88 01 8b 45 ?? 0f b6 00 8b 4d ?? fe c0 88 01 8b 45 ?? 0f b6 00 8b 4d d4 88 01 8b 45 ?? 8b 45 d0 8b 45 d0 8b 45 d0 b8 49 d2 18 71 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}