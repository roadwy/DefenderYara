
rule Trojan_Win32_Qbot_RRR_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e8 2c 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 8b 5d 90 01 01 83 c3 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}