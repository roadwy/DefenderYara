
rule Trojan_Win32_Trickbot_SM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 53 51 8b c6 46 8b 00 8b 0f 33 c1 88 07 47 4b 58 8b c8 75 06 58 2b f0 50 8b d8 49 75 e4 59 58 59 5e 5f 5b c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}