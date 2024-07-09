
rule Worm_Win32_Pushbot_UI{
	meta:
		description = "Worm:Win32/Pushbot.UI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 55 73 65 72 73 5c 68 65 78 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 54 72 61 76 65 6c 65 72 7a 5c 56 42 36 2e 4f 4c 42 } //1 C:\Users\hex\AppData\Local\Temp\Travelerz\VB6.OLB
		$a_00_1 = {53 61 6c 6d 61 6e 64 6f 73 } //1 Salmandos
		$a_03_2 = {fc 06 00 00 c7 45 fc ?? 00 00 00 c7 85 ?? ?? ff ff ?? ?? 40 00 c7 85 ?? fe ff ff 08 00 00 00 8d ?? ?? ?? 8d ?? ?? fe ff ff ?? 8d ?? ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}