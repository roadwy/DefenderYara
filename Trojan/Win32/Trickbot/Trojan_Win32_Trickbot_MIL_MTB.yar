
rule Trojan_Win32_Trickbot_MIL_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MIL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 bf 29 00 00 00 f7 f7 8b 7c 24 0c 8a 04 39 8a 54 14 44 32 c2 88 04 39 41 81 f9 e0 07 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}