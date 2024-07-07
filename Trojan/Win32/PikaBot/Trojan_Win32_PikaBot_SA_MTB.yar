
rule Trojan_Win32_PikaBot_SA_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 15 90 01 01 33 c8 3a d2 74 90 01 01 8b 45 90 01 01 8b 40 90 01 01 eb 90 01 01 8b 45 90 01 01 0f b6 4c 05 90 01 01 66 3b c0 74 90 01 01 89 45 90 01 01 8b 45 90 01 01 e9 90 01 04 8b 45 90 01 01 8b 00 e9 90 01 04 c9 c3 8b 45 90 01 01 40 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}