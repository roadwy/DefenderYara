
rule Trojan_Win32_Inject_ZH_bit{
	meta:
		description = "Trojan:Win32/Inject.ZH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 8a 8c 15 90 01 04 8b 9d 70 90 01 03 8b 85 e0 90 01 03 30 0c 03 90 00 } //01 00 
		$a_03_1 = {ff 8a 8c 15 90 01 04 8b 9d 90 01 04 8b 03 8b 95 b0 90 01 03 30 0c 10 90 00 } //01 00 
		$a_03_2 = {8a 04 11 8b 95 90 01 04 8b 8d 90 01 04 30 04 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}