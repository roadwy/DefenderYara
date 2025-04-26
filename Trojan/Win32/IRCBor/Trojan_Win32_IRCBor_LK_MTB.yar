
rule Trojan_Win32_IRCBor_LK_MTB{
	meta:
		description = "Trojan:Win32/IRCBor.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe c1 8a 04 19 8a 14 18 88 04 1a 88 14 18 30 07 47 4d 75 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}