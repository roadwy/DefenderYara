
rule Trojan_Win32_IRCBot_MR_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {47 21 fb 40 90 02 02 81 90 02 05 21 90 01 01 39 90 01 01 90 18 b9 90 02 04 81 90 02 05 09 90 01 01 e8 90 02 04 81 90 02 05 29 90 01 01 01 90 01 01 31 90 01 01 bb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}