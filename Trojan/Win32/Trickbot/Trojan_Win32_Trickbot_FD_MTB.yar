
rule Trojan_Win32_Trickbot_FD_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b db 11 89 86 c0 05 00 00 29 d8 8b 9e c0 05 00 00 81 eb 61 47 ea e3 01 d8 8b 9e c0 05 00 00 29 c3 81 eb 06 0a 6d 5a 83 eb d5 81 c3 06 0a 6d 5a 8b 86 c0 05 00 00 2d 61 47 ea e3 01 c3 89 d8 89 96 bc 05 00 00 99 bb 7f 00 00 00 f7 fb 88 17 8b 96 20 06 00 00 8a 52 01 88 96 8b 06 00 00 89 be 84 06 00 00 0f b6 96 8b 06 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}