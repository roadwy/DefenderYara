
rule Trojan_Win32_Trickbot_DDE_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DDE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8b 54 24 18 8b c1 8b f2 f7 d0 f7 d6 5f 0b c6 5e 0b ca 5d 23 c1 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}