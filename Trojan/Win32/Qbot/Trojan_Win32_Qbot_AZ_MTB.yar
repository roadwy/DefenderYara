
rule Trojan_Win32_Qbot_AZ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 68 03 90 01 03 ff 15 90 01 04 03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}