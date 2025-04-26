
rule Trojan_Win32_Spybot_RPB_MTB{
	meta:
		description = "Trojan:Win32/Spybot.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 0c 24 c1 24 24 04 8b 44 24 0c 01 04 24 89 4c 24 04 c1 6c 24 04 05 8b 44 24 14 01 44 24 04 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 33 04 24 83 c4 08 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}