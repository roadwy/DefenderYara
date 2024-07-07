
rule Trojan_Win32_Trickbot_RB_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.RB!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 0c 53 57 8b 7c 24 10 8a 1c 08 8b d0 83 e2 1f 8a 14 3a 32 da 88 1c 08 40 3b c6 75 eb 5f 5b 5e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}