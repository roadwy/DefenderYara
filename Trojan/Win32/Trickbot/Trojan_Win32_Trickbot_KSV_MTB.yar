
rule Trojan_Win32_Trickbot_KSV_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 0c 59 33 d2 8b c6 f7 f1 c7 04 24 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? e8 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}