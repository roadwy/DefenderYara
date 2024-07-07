
rule Trojan_Win32_Trickbot_DG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 02 8b 4d 90 01 01 03 4d 90 01 01 81 e1 90 01 04 33 d2 8a 94 90 01 05 33 c2 8b 4d 90 01 01 03 4d 90 01 01 88 01 e9 90 0a a4 00 83 c2 01 89 55 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 8d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}