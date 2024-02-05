
rule Trojan_Win32_IRCBot_EM_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 3e 21 c9 81 c3 01 00 00 00 81 c6 01 00 00 00 39 c6 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}