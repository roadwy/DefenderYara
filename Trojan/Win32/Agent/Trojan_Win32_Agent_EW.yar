
rule Trojan_Win32_Agent_EW{
	meta:
		description = "Trojan:Win32/Agent.EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c0 74 2f 8b 8d 90 01 04 0f be 91 90 01 04 83 f2 77 85 d2 74 1b 8b 85 90 01 04 8a 88 90 01 04 80 f1 77 8b 95 90 01 04 88 8a 90 01 04 eb a3 90 00 } //01 00 
		$a_03_1 = {8a 02 34 21 8b 8d 90 01 04 03 8d 90 01 04 88 01 eb c3 8b 15 90 01 04 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}