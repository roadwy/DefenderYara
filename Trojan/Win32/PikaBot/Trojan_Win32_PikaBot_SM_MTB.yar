
rule Trojan_Win32_PikaBot_SM_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 8b 45 90 01 01 eb 90 01 01 bb 90 01 04 83 c3 90 01 01 eb 90 01 01 bb 90 01 04 21 5d 90 01 01 e9 90 00 } //01 00 
		$a_03_1 = {0f b6 44 10 90 01 01 33 c8 eb 90 01 01 21 5d 90 01 01 e9 90 01 04 8b 45 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}