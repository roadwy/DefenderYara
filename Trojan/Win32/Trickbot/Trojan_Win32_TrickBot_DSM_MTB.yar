
rule Trojan_Win32_TrickBot_DSM_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 f8 74 90 01 01 33 d2 f7 75 fc 8b 45 f8 8a 0c 55 90 02 04 30 0c 18 40 3b c6 89 45 f8 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}