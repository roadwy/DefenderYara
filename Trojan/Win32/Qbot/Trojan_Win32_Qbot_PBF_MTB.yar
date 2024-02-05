
rule Trojan_Win32_Qbot_PBF_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c3 01 83 c3 00 90 13 53 5e 66 3b ff 90 13 f7 f6 8b 45 fc 66 3b ed 90 13 0f b6 44 10 90 01 01 33 c8 66 3b c9 90 13 8b 45 90 01 01 03 45 90 01 01 90 13 88 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}