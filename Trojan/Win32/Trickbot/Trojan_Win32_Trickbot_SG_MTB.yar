
rule Trojan_Win32_Trickbot_SG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 78 18 10 72 ?? 83 c0 04 8b 00 eb ?? 83 c0 04 8a 04 38 30 06 8b 45 ?? 2b 45 ?? 43 3b d8 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}