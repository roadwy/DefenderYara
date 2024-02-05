
rule Trojan_Win32_Emotet_DCM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 03 c1 b9 90 01 04 99 f7 f9 8b 44 24 90 01 01 8a 4c 14 90 01 01 30 08 90 02 03 ff 4c 24 90 01 01 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}