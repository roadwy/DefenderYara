
rule Trojan_Win32_Zbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 40 00 01 01 ec 71 40 00 41 00 01 01 08 72 40 00 63 00 00 00 28 72 40 00 64 00 00 00 28 72 40 00 62 00 01 01 54 72 40 } //00 00 
	condition:
		any of ($a_*)
 
}