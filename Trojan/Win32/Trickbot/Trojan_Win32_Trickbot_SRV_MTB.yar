
rule Trojan_Win32_Trickbot_SRV_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SRV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {bf e0 07 00 00 6a 40 68 00 30 00 00 90 01 08 2b df ff 55 90 01 08 8d 0c 1f 90 01 02 ff 55 90 01 01 83 c4 0c 90 01 01 6a 40 68 00 30 00 00 90 01 02 ff 75 90 01 01 ff 55 90 01 01 8b f0 90 01 03 ff 55 90 01 01 8d 45 90 01 01 6a 90 01 04 ff 55 90 01 01 83 c4 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}