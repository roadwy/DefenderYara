
rule Trojan_Win32_IRCBot_MR_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {47 21 fb 40 [0-02] 81 [0-05] 21 ?? 39 ?? 90 18 b9 [0-04] 81 [0-05] 09 ?? e8 [0-04] 81 [0-05] 29 ?? 01 ?? 31 ?? bb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}