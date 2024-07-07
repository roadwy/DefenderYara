
rule Trojan_Win32_Trickbot_DHN_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 c1 99 b9 9d 15 00 00 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 08 90 00 } //1
		$a_81_1 = {32 53 75 62 61 57 41 61 52 7a 66 47 65 59 39 6d 57 32 67 54 68 41 37 54 44 79 4e 70 56 4c 7a 66 36 } //1 2SubaWAaRzfGeY9mW2gThA7TDyNpVLzf6
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}