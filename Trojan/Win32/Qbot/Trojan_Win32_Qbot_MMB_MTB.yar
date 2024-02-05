
rule Trojan_Win32_Qbot_MMB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b 0d 90 01 04 83 c1 01 a1 90 01 04 a3 90 01 04 a1 90 01 04 33 c1 8b ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}