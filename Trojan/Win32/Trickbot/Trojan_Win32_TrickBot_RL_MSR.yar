
rule Trojan_Win32_TrickBot_RL_MSR{
	meta:
		description = "Trojan:Win32/TrickBot.RL!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 90 01 01 8b 55 08 52 e8 90 01 02 00 00 83 c4 04 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb be 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}