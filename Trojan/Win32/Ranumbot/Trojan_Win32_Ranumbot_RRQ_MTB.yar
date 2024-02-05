
rule Trojan_Win32_Ranumbot_RRQ_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 eb 05 89 5d 70 c7 05 90 01 04 2e ce 50 91 8b 85 90 01 04 01 45 70 81 3d 90 01 04 12 09 00 00 75 90 00 } //01 00 
		$a_02_1 = {c1 e8 05 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8d 04 16 50 8b 45 90 01 01 e8 90 01 04 33 45 90 01 01 89 3d 90 01 04 8b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}