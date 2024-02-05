
rule Trojan_Win32_Trickbot_VC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 15 90 01 04 0f b6 c3 03 c1 99 b9 90 01 04 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 4e 90 01 01 8b 8d 90 01 04 4f 90 00 } //01 00 
		$a_03_1 = {8a 1c 38 30 19 03 ce 03 fe 90 13 3b ca 90 13 83 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}