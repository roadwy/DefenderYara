
rule Trojan_Win32_Trickbot_KSP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff d7 8a 16 6a 00 32 d3 02 d3 88 16 ff d7 46 4d 75 } //2
		$a_02_1 = {8b c6 f7 f3 8b 44 24 ?? 8a 04 02 30 01 46 3b 74 24 ?? 75 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}