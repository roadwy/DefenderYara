
rule Trojan_Win32_Qbot_PVE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b ff 33 c1 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 5f 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}