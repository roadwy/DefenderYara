
rule Trojan_Win32_Emotet_CQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 d8 ba 93 24 49 92 43 d1 e8 f7 e2 c1 ea 02 6b c2 f2 8b 56 08 0f b6 04 01 41 30 84 3a 00 34 02 00 47 75 dc } //00 00 
	condition:
		any of ($a_*)
 
}