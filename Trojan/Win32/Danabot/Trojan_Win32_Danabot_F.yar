
rule Trojan_Win32_Danabot_F{
	meta:
		description = "Trojan:Win32/Danabot.F,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 fe 00 74 36 29 c0 48 23 02 83 ea fc f7 d8 83 e8 26 8d 40 fe 83 c0 01 29 f8 6a ff 5f 21 c7 c7 41 00 00 00 00 00 31 01 83 c1 04 83 ee 04 8d 05 0f 45 41 00 2d 65 98 00 00 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}