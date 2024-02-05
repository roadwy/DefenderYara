
rule Trojan_Win32_Killav_P{
	meta:
		description = "Trojan:Win32/Killav.P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 51 50 50 50 50 68 04 80 22 00 ff 75 f8 ff 15 90 01 04 60 b8 01 00 00 00 61 ff 90 01 02 e8 90 01 04 59 50 6a 00 6a 01 ff 15 90 01 04 6a 00 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}