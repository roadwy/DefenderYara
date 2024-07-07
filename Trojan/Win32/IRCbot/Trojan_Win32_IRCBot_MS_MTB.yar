
rule Trojan_Win32_IRCBot_MS_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c6 01 8b 90 02 02 8d 90 02 02 89 90 01 01 8b 90 02 02 8a 90 02 03 30 90 01 01 8d 90 02 02 89 90 01 01 81 90 02 05 90 18 39 90 01 01 77 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}