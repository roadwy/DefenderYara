
rule Trojan_Win32_Qbot_PAO_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 45 a4 8b 45 90 01 01 8b 55 90 01 01 01 02 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 90 01 04 8b 55 a0 2b d0 8b 45 90 01 01 33 10 89 55 90 01 01 8b 45 90 01 01 8b 55 90 01 01 89 02 8b 45 a8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}