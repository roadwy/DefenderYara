
rule Trojan_Win32_TrickBot_CG_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 6e 04 eb 90 01 01 8d 6e 04 33 d2 8b 90 01 01 f7 f3 8a 90 01 02 30 90 01 01 47 eb 90 0a 40 00 8b 90 01 02 2b 90 01 01 3b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}