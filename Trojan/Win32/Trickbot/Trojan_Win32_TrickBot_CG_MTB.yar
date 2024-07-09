
rule Trojan_Win32_TrickBot_CG_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 6e 04 eb ?? 8d 6e 04 33 d2 8b ?? f7 f3 8a ?? ?? 30 ?? 47 eb 90 0a 40 00 8b ?? ?? 2b ?? 3b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}