
rule Trojan_Win32_PikaBot_DS_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5e f7 f6 eb 90 01 01 83 c3 90 01 01 53 3a ff 74 90 01 01 33 c8 8b 45 90 01 01 eb 90 01 01 8b 00 89 45 90 01 01 e9 90 01 04 8b 45 90 01 01 48 e9 90 01 04 89 45 90 01 01 e9 90 01 04 8b 45 90 01 01 eb 90 01 01 03 41 90 01 01 39 45 90 01 01 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}