
rule Trojan_Win32_IRCBot_RM_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 10 14 40 00 c3 39 ff 74 90 01 01 ea 31 07 4b 4b 81 c7 04 00 00 00 39 d7 75 90 01 01 68 b1 b6 30 22 8b 34 24 83 c4 04 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}