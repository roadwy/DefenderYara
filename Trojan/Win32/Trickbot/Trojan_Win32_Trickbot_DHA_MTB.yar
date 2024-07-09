
rule Trojan_Win32_Trickbot_DHA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 76 00 8b b5 ?? ?? ?? ?? 89 c8 31 d2 f7 76 f4 0f b6 04 16 30 04 0b 83 c1 01 39 f9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}