
rule Trojan_Win32_Sefnit_AV{
	meta:
		description = "Trojan:Win32/Sefnit.AV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 8b d7 8a 1c 01 80 f3 90 01 01 88 18 40 4a 75 f4 90 00 } //01 00 
		$a_03_1 = {7e 60 8b 45 0c 8d 34 b8 68 90 01 04 ff 36 e8 90 01 04 59 59 85 c0 74 72 68 90 01 04 ff 36 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}