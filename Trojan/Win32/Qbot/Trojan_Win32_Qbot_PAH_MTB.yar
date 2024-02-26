
rule Trojan_Win32_Qbot_PAH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 1c 8b 95 0c 01 00 00 8b 45 04 8a 0c 39 32 0c 02 } //00 00 
	condition:
		any of ($a_*)
 
}