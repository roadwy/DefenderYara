
rule Trojan_Win32_Pikabot_RPX_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 46 08 eb 3c 8b 4e 50 8b 46 38 83 c1 3f 8b 15 90 01 04 03 c1 50 81 c2 00 30 00 00 52 ff 35 90 01 04 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}