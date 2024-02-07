
rule Trojan_Win32_AtlasClipper_SK_MTB{
	meta:
		description = "Trojan:Win32/AtlasClipper.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 4d 75 74 65 78 } //02 00  YourMutex
		$a_01_1 = {41 54 4c 41 53 20 43 6c 69 70 70 65 72 } //02 00  ATLAS Clipper
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 61 74 6c 61 73 63 6c 69 70 70 65 72 5f 63 68 61 6e 6e 65 6c } //00 00  https://t.me/atlasclipper_channel
	condition:
		any of ($a_*)
 
}