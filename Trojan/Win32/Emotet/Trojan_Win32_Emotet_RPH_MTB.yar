
rule Trojan_Win32_Emotet_RPH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ab ab ab ab 8b 7d bc b9 14 00 00 00 b8 44 00 00 00 57 ab 33 c0 ab e2 fd } //00 00 
	condition:
		any of ($a_*)
 
}