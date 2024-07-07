
rule Trojan_Win32_Trickbot_KSV_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 0c 59 33 d2 8b c6 f7 f1 c7 04 24 90 01 04 8a 82 90 01 04 30 86 90 01 04 e8 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}