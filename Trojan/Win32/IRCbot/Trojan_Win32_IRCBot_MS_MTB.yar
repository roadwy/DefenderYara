
rule Trojan_Win32_IRCBot_MS_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c6 01 8b [0-02] 8d [0-02] 89 ?? 8b [0-02] 8a [0-03] 30 ?? 8d [0-02] 89 ?? 81 [0-05] 90 18 39 ?? 77 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}