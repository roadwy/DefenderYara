
rule Trojan_Win32_Trickbot_MG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 8b 74 24 ?? 55 53 8b 5c 24 ?? 8b ?? 33 ?? bd [0-04] f7 f5 8a ?? ?? 8a ?? ?? 32 ?? 88 ?? ?? 41 3b cf 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}