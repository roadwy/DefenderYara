
rule Trojan_BAT_Lokibot_AGJD_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AGJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d ca 06 03 07 8f } //01 00 
		$a_01_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 54 00 65 00 72 00 6d 00 69 00 6e 00 61 00 6c 00 2e 00 57 00 70 00 66 00 2e 00 64 00 6c 00 6c 00 } //00 00  Microsoft.Terminal.Wpf.dll
	condition:
		any of ($a_*)
 
}