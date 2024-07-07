
rule Trojan_Win32_IRCBot_EC_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 fc 0f b6 10 33 14 8d 90 01 04 8b 45 08 03 45 fc 88 10 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}