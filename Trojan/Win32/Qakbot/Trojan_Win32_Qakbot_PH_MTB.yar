
rule Trojan_Win32_Qakbot_PH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 66 3b c0 74 ?? 80 45 ?? 46 e9 ?? ?? ?? ?? c6 45 ?? 1f eb ?? c6 45 ?? 40 80 45 ?? 12 3a f6 74 ?? c6 45 ?? 4c 80 45 ?? 20 66 3b e4 74 ?? c6 45 ?? 24 80 45 ?? 20 3a f6 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}