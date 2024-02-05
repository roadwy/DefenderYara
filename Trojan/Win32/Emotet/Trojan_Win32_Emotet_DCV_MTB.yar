
rule Trojan_Win32_Emotet_DCV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 54 24 24 0f be 04 2a 8a 54 24 18 8a c8 f6 d1 f6 d2 0a d1 8a 4c 24 90 01 01 0a c8 8b 44 24 90 01 01 22 d1 88 14 28 90 02 03 3b 6c 24 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}