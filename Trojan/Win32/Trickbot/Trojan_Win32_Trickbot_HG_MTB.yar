
rule Trojan_Win32_Trickbot_HG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 [0-09] 3b 78 14 [0-11] 83 c0 04 8b 00 eb ?? 83 c0 04 8a ?? ?? 30 ?? 8b [0-09] 3b ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}