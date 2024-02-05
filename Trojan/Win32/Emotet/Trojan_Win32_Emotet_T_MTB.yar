
rule Trojan_Win32_Emotet_T_MTB{
	meta:
		description = "Trojan:Win32/Emotet.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d7 33 d2 8b c6 f7 f5 8b 44 24 14 8a 0c 50 8a 14 1e 8b 44 24 1c 32 d1 88 14 1e 46 3b f0 75 90 01 01 5f 5d 5b 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}