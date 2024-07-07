
rule Trojan_Win32_Trickbot_CF_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d6 8b 75 90 01 01 8d 04 0a 66 8b 14 5e 66 03 14 7e 66 83 e2 0f 79 90 01 01 66 4a 66 83 ca f0 66 42 0f bf d2 8a 14 56 30 10 b8 01 00 00 00 03 c8 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}