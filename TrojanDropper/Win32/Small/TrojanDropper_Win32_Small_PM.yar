
rule TrojanDropper_Win32_Small_PM{
	meta:
		description = "TrojanDropper:Win32/Small.PM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 33 20 2d 20 36 36 36 00 } //1
		$a_03_1 = {b8 01 00 00 00 85 c0 74 30 6a 0a ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc } //1
		$a_03_2 = {8b 55 08 03 55 fc 8a 02 2c ?? 8b 4d 08 03 4d fc 88 01 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}