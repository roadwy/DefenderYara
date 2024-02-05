
rule Trojan_Win32_Trickbot_DSE_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 84 24 90 02 00 00 0f b6 cb 8a 1c 07 8a 54 0c 1c 32 da 88 1c 07 8b 84 24 94 02 00 00 47 3b f8 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}