
rule Trojan_Win32_Satacom_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Satacom.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d a0 8b 34 37 c1 ee 08 33 d6 8b 75 a0 8b 34 06 03 f2 8b 45 98 33 d2 f7 b5 68 ff ff ff 8b 45 0c 03 34 90 03 75 98 8b 55 a0 8b 04 0a 2b c6 89 85 64 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}