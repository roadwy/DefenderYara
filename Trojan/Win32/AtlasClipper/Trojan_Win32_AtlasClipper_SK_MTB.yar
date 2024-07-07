
rule Trojan_Win32_AtlasClipper_SK_MTB{
	meta:
		description = "Trojan:Win32/AtlasClipper.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 4d 75 74 65 78 } //2 YourMutex
		$a_01_1 = {41 54 4c 41 53 20 43 6c 69 70 70 65 72 } //2 ATLAS Clipper
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 61 74 6c 61 73 63 6c 69 70 70 65 72 5f 63 68 61 6e 6e 65 6c } //2 https://t.me/atlasclipper_channel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}