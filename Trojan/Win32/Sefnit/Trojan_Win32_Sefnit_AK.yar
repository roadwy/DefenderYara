
rule Trojan_Win32_Sefnit_AK{
	meta:
		description = "Trojan:Win32/Sefnit.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 75 18 8b 45 f4 ff 75 14 03 c6 ff 75 10 ff 75 0c a3 90 01 04 ff 75 08 ff 15 90 00 } //01 00 
		$a_03_1 = {6b f6 28 8d 74 32 04 90 02 10 83 3e 00 74 90 02 10 83 c6 04 83 90 02 02 0a 7c 90 01 01 eb 90 02 08 6b 90 01 01 0a 90 02 10 89 90 01 02 04 90 00 } //01 00 
		$a_03_2 = {0f be c3 69 c0 90 02 08 05 90 01 04 90 03 01 01 e9 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}