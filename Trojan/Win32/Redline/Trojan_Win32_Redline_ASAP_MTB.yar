
rule Trojan_Win32_Redline_ASAP_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e1 06 0b c1 88 45 ee 0f b6 55 ee 81 ea 84 00 00 00 88 55 ee 0f b6 45 ee f7 d8 88 45 ee 0f b6 4d ee 03 4d e0 88 4d ee 8b 55 e0 8a 45 ee 88 44 15 b0 e9 } //01 00 
		$a_01_1 = {8b 45 dc 83 c0 01 89 45 dc 81 7d dc 12 e3 f5 05 7d 0b 8b 4d d8 83 c1 01 89 4d d8 eb } //00 00 
	condition:
		any of ($a_*)
 
}