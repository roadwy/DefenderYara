
rule Trojan_Win32_QakbotPacker_AZ_MTB{
	meta:
		description = "Trojan:Win32/QakbotPacker.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 03 05 90 01 04 03 d8 90 02 10 03 d8 a1 90 01 04 89 18 a1 90 01 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 8b 00 33 05 90 01 04 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 a1 90 01 04 83 c0 04 a3 90 01 04 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 03 05 90 01 04 a3 90 01 04 a1 90 01 04 3b 05 90 01 04 90 13 a1 90 01 04 03 05 90 01 04 48 a3 90 01 04 90 02 10 8b d8 a1 90 01 04 8b 00 03 05 90 01 04 03 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}