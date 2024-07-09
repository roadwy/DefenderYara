
rule Trojan_Win32_Small_CH{
	meta:
		description = "Trojan:Win32/Small.CH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ac 84 c0 75 fb 83 ee 05 81 0e 20 20 20 20 81 3e 2e 65 78 65 0f ?? ?? ?? 00 00 0f b7 46 fe 0d 20 20 00 00 3d 71 71 00 00 0f ?? ?? ?? 00 00 8b 46 f9 0d 20 20 20 20 3d 74 68 75 6e 0f ?? ?? ?? 00 00 } //1
		$a_01_1 = {0b c9 74 24 f7 43 24 00 00 00 20 74 1b 2b 4b 08 81 f9 24 04 00 00 76 10 81 4b 24 00 00 00 c0 81 43 08 24 04 00 00 eb 1b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}